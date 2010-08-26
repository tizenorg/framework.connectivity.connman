/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
 *  Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>

#include <gdbus.h>
#include <string.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/element.h>
#include <connman/device.h>
#include <connman/network.h>
#include <connman/dbus.h>
#include <connman/inet.h>
#include <connman/log.h>

#define OFONO_SERVICE			"org.ofono"

#define OFONO_MANAGER_INTERFACE		OFONO_SERVICE ".Manager"
#define OFONO_MODEM_INTERFACE		OFONO_SERVICE ".Modem"
#define OFONO_GPRS_INTERFACE		OFONO_SERVICE ".DataConnectionManager"
#define OFONO_SIM_INTERFACE		OFONO_SERVICE ".SimManager"
#define OFONO_PRI_CONTEXT_INTERFACE	OFONO_SERVICE ".PrimaryDataContext"
#define OFONO_REGISTRATION_INTERFACE	OFONO_SERVICE ".NetworkRegistration"

#define PROPERTY_CHANGED		"PropertyChanged"
#define GET_PROPERTIES			"GetProperties"
#define SET_PROPERTY			"SetProperty"
#define CREATE_CONTEXT			"CreateContext"

#define TIMEOUT 5000

#define CONTEXT_NAME "3G Connection"
#define CONTEXT_TYPE "internet"

static DBusConnection *connection;

static GHashTable *modem_hash = NULL;

struct modem_data {
	char *path;
	struct connman_device *device;
	gboolean available;
};

static int modem_probe(struct connman_device *device)
{
	DBG("device %p", device);

	return 0;
}

static void modem_remove(struct connman_device *device)
{
	DBG("device %p", device);
}

static int call_ofono(const char *path,
			const char *interface, const char *method,
			DBusPendingCallNotifyFunction notify, void *user_data,
			DBusFreeFunction free_function,
			int type, ...)
{
	DBusMessage *message;
	DBusPendingCall *call;
	dbus_bool_t ok;
	va_list va;

	DBG("path %s %s.%s", path, interface, method);

	if (path == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(OFONO_SERVICE, path,
					interface, method);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	va_start(va, type);
	ok = dbus_message_append_args_valist(message, type, va);
	va_end(va);

	if (!ok)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to call %s.%s", interface, method);
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	dbus_pending_call_set_notify(call, notify, user_data, free_function);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static void set_property_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	char const *name = user_data;

	DBG("");

	dbus_error_init(&error);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("SetProperty(%s) %s %s", name,
				error.name, error.message);
		dbus_error_free(&error);
	}

	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int set_property(const char *path, const char *interface,
			const char *property, int type, void *value,
			DBusPendingCallNotifyFunction notify, void *user_data,
			DBusFreeFunction free_function)
{
	DBusMessage *message;
	DBusMessageIter iter;
	DBusPendingCall *call;

	DBG("path %s %s.%s", path, interface, property);

	g_assert(notify == NULL ? free_function == NULL : 1);

	if (path == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(OFONO_SERVICE, path,
					interface, SET_PROPERTY);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	dbus_message_iter_init_append(message, &iter);
	connman_dbus_property_append_basic(&iter, property, type, value);

	if (dbus_connection_send_with_reply(connection, message,
						&call, TIMEOUT) == FALSE) {
		connman_error("Failed to change \"%s\" property on %s",
				property, interface);
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (call == NULL) {
		connman_error("D-Bus connection not available");
		dbus_message_unref(message);
		return -EINVAL;
	}

	if (notify == NULL) {
		notify = set_property_reply;
		user_data = (void *)property;
		free_function = NULL;
	}

	dbus_pending_call_set_notify(call, notify, user_data, free_function);

	dbus_message_unref(message);

	return -EINPROGRESS;
}

static int gprs_change_powered(const char *path, dbus_bool_t powered)
{
	DBG("path %s powered %d", path, powered);

	return set_property(path, OFONO_GPRS_INTERFACE, "Powered",
				DBUS_TYPE_BOOLEAN, &powered,
				NULL, NULL, NULL);
}

static int modem_enable(struct connman_device *device)
{
	const char *path = connman_device_get_string(device, "Path");

	DBG("device %p, path, %s", device, path);

	return gprs_change_powered(path, TRUE);
}

static int modem_disable(struct connman_device *device)
{
	const char *path = connman_device_get_string(device, "Path");

	DBG("device %p, path %s", device, path);

	return gprs_change_powered(path, FALSE);
}

static struct connman_device_driver modem_driver = {
	.name		= "modem",
	.type		= CONNMAN_DEVICE_TYPE_CELLULAR,
	.probe		= modem_probe,
	.remove		= modem_remove,
	.enable		= modem_enable,
	.disable	= modem_disable,
};

static char *get_ident(const char *path)
{
	char *pos;

	if (*path != '/')
		return NULL;

	pos = strrchr(path, '/');
	if (pos == NULL)
		return NULL;

	return pos + 1;
}

static void create_service(struct connman_network *network)
{
	const char *path;
	char *group;

	DBG("");

	path = connman_network_get_string(network, "Path");

	group = get_ident(path);

	connman_network_set_group(network, group);
}

static void set_network_name_reply(DBusPendingCall *call, void *user_data)
{
	struct connman_network *network = user_data;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("network %p", network);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		/*
		 * 'Operator' is deprecated since version 0.20, but
		 * keep it here for backward compatibility reasons.
		 */
		if (g_str_equal(key, "Operator") == TRUE ||
				g_str_equal(key, "Name") == TRUE) {
			const char *name;

			dbus_message_iter_get_basic(&value, &name);
			connman_network_set_name(network, name);
			create_service(network);
		} else if (g_strcmp0(key, "Status") == 0) {
			const char *status;
			connman_bool_t roaming;

			dbus_message_iter_get_basic(&value, &status);
			if (g_strcmp0(status, "roaming") == 0)
				roaming = TRUE;
			else if (g_strcmp0(status, "registered") == 0)
				roaming = FALSE;
			else {
				dbus_message_iter_next(&dict);
				continue;
			}

			connman_network_set_roaming(network, roaming);
			connman_network_update(network);
		}

		dbus_message_iter_next(&dict);
	}
done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static void set_network_name(struct connman_network *network)
{
	struct connman_device *device;
	const char *path;

	device = connman_network_get_device(network);

	path = connman_device_get_string(device, "Path");
	if (path == NULL)
		return;

	DBG("path %s", path);

	call_ofono(path, OFONO_REGISTRATION_INTERFACE, GET_PROPERTIES,
			set_network_name_reply, network, NULL,
			DBUS_TYPE_INVALID);
}

static void config_network_reply(DBusPendingCall *call, void *user_data)
{
	struct connman_network *network = user_data;
	DBusMessage *reply;
	DBusMessageIter array, dict;
	gboolean internet_type = FALSE;

	DBG("network %p", network);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Type") == TRUE) {
			const char *type;

			dbus_message_iter_get_basic(&value, &type);
			if (g_strcmp0(type, "internet") == 0) {
				internet_type = TRUE;

				connman_network_set_protocol(network,
						CONNMAN_NETWORK_PROTOCOL_IP);
				set_network_name(network);
			} else {
				internet_type = FALSE;

				connman_network_set_protocol(network,
					CONNMAN_NETWORK_PROTOCOL_UNKNOWN);
			}
		}

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static void config_network(struct connman_network *network, const char *path)
{
	DBG("path %s", path);

	call_ofono(path, OFONO_PRI_CONTEXT_INTERFACE, GET_PROPERTIES,
			config_network_reply, network, NULL,
			DBUS_TYPE_INVALID);
}

static gboolean registration_changed(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct connman_network *network = user_data;
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	DBG("key %s", key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_strcmp0(key, "Name") == 0 ||
			g_strcmp0(key, "Operator") == 0) {
		const char *name;

		dbus_message_iter_get_basic(&value, &name);
		DBG("name %s", name);
		connman_network_set_name(network, name);
		create_service(network);
	} else if (g_strcmp0(key, "Strength") == 0) {
		connman_uint8_t strength;

		dbus_message_iter_get_basic(&value, &strength);
		connman_network_set_strength(network, strength);
		connman_network_update(network);
	} else if (g_strcmp0(key, "Status") == 0) {
		const char *status;
		connman_bool_t roaming;

		dbus_message_iter_get_basic(&value, &status);
		if (g_strcmp0(status, "roaming") == 0)
			roaming = TRUE;
		else if (g_strcmp0(status, "registered") == 0)
			roaming = FALSE;
		else
			return TRUE;

		connman_network_set_roaming(network, roaming);
		connman_network_update(network);
	}

	return TRUE;
}

static int network_probe(struct connman_network *network)
{
	const char *path;
	guint reg_watch;

	reg_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_REGISTRATION_INTERFACE,
						PROPERTY_CHANGED,
						registration_changed,
						network, NULL);
	if (reg_watch == 0)
		return -EIO;

	connman_network_set_data(network, GUINT_TO_POINTER(reg_watch));

	path = connman_network_get_string(network, "Path");

	DBG("network %p path %s", network, path);

	config_network(network, path);

	return 0;
}

static struct connman_network *pending_network;

static gboolean pending_network_is_available(
		struct connman_network *pending_network)
{
	struct connman_device *device;
	struct connman_network *network;
	const char *identifier;
	char *ident;

	/* Modem may be removed during waiting for active reply */
	device  = connman_network_get_device(pending_network);
	if (device == NULL) {
		DBG("Modem is removed");
		return FALSE;
	}

	identifier = connman_network_get_identifier(pending_network);

	ident = g_strdup(identifier);

	connman_network_unref(pending_network);

	/* network may be removed during waiting for active reply */
	network = connman_device_get_network(device, ident);

	g_free(ident);

	if (network == NULL)
		return FALSE;

	return TRUE;
}

static void set_active_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	struct connman_network *network = user_data;

	DBG("network %p", network);

	reply = dbus_pending_call_steal_reply(call);

	if (pending_network_is_available(network) == FALSE)
		goto done;

	dbus_error_init(&error);
	if (dbus_set_error_from_message(&error, reply)) {
		if (connman_network_get_index(network) < 0)
			connman_network_set_error(network,
				CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL);

		pending_network = NULL;

		connman_error("SetProperty(Active) %s %s",
				error.name, error.message);

		dbus_error_free(&error);
	} else
		pending_network = network;

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static int set_network_active(struct connman_network *network,
						dbus_bool_t active)
{
	int error;

	const char *path = connman_network_get_string(network, "Path");

	DBG("network %p, path %s, active %d", network, path, active);

	error = set_property(path, OFONO_PRI_CONTEXT_INTERFACE,
				"Active", DBUS_TYPE_BOOLEAN, &active,
				set_active_reply, network, NULL);
	if (active == FALSE && error == -EINPROGRESS)
		error = 0;

	return error;
}

static void set_apn(struct connman_network *network)
{
	const char *apn, *path;

	apn = connman_network_get_string(network, "Cellular.APN");
	if (apn == NULL)
		return;

	path = connman_network_get_string(network, "Path");
	if (path == NULL)
		return;

	DBG("path %s, apn %s", path, apn);

	set_property(path, OFONO_PRI_CONTEXT_INTERFACE,
			"AccessPointName", DBUS_TYPE_STRING, &apn,
			NULL, NULL, NULL);
}

static int network_connect(struct connman_network *network)
{
	if (connman_network_get_index(network) >= 0)
		return -EISCONN;

	return set_network_active(network, TRUE);
}

static int network_disconnect(struct connman_network *network)
{
	if (connman_network_get_index(network) < 0)
		return -ENOTCONN;

	return set_network_active(network, FALSE);
}

static void network_remove(struct connman_network *network)
{
	guint reg_watch;

	DBG("network %p", network);

	reg_watch = GPOINTER_TO_UINT(connman_network_get_data(network));
	g_dbus_remove_watch(connection, reg_watch);
}

static int network_setup(struct connman_network *network, const char *key)
{
	DBG("");

	if (g_strcmp0(key, "Cellular.APN") == 0)
		set_apn(network);

	return 0;
}

static struct connman_network_driver network_driver = {
	.name		= "network",
	.type		= CONNMAN_NETWORK_TYPE_CELLULAR,
	.probe		= network_probe,
	.remove		= network_remove,
	.connect	= network_connect,
	.disconnect	= network_disconnect,
	.setup		= network_setup,
};

static void add_network(struct connman_device *device, const char *path)
{
	struct connman_network *network;
	char *ident;
	const char *mcc;
	const char *mnc;

	DBG("device %p path %s", device, path);

	network = connman_device_get_network(device, path);
	if (network != NULL)
		return;

	ident = get_ident(path);

	network = connman_network_create(ident,
					CONNMAN_NETWORK_TYPE_CELLULAR);
	if (network == NULL)
		return;

	connman_network_set_string(network, "Path", path);
	connman_network_set_available(network, TRUE);
	connman_network_set_index(network, -1);

	mcc = connman_device_get_string(device, "MCC");
	if (mcc != NULL)
		connman_network_set_string(network, "Cellular.MCC", mcc);

	mnc = connman_device_get_string(device, "MNC");
	if (mnc != NULL)
		connman_network_set_string(network, "Cellular.MNC", mnc);

	connman_device_add_network(device, network);
}

static void add_networks(struct connman_device *device, DBusMessageIter *array)
{
	DBusMessageIter entry;

	DBG("");

	dbus_message_iter_recurse(array, &entry);

	while (dbus_message_iter_get_arg_type(&entry) ==
					DBUS_TYPE_OBJECT_PATH) {
		const char *path;

		dbus_message_iter_get_basic(&entry, &path);

		add_network(device, path);

		dbus_message_iter_next(&entry);
	}
}

static void create_context_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;

	DBG("");

	dbus_error_init(&error);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("CreateContext() %s %s",
				error.name, error.message);
		dbus_error_free(&error);
	}

	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static void add_default_context(DBusMessageIter *array,
		const char *path, const char *name, const char *type)
{
	DBusMessageIter entry;

	if (path == NULL)
		return;

	DBG("");

	dbus_message_iter_recurse(array, &entry);

	if (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_OBJECT_PATH)
		return;

	DBG("path %s, name %s, type %s", path, name, type);

	call_ofono(path, OFONO_GPRS_INTERFACE, CREATE_CONTEXT,
			create_context_reply, NULL, NULL,
			DBUS_TYPE_STRING, &name,
			DBUS_TYPE_STRING, &type,
			DBUS_TYPE_INVALID);
}

static void check_networks_reply(DBusPendingCall *call, void *user_data)
{
	char *path = user_data;
	struct modem_data *modem;
	struct connman_device *device;
	DBusMessage *reply;
	DBusMessageIter array, dict, contexts;
	dbus_bool_t attached;

	DBG("path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL || modem->device == NULL)
		return;

	device = modem->device;

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		DBG("key %s", key);

		if (g_str_equal(key, "Attached") == TRUE) {
			dbus_message_iter_get_basic(&value, &attached);
			DBG("Attached %d", attached);
		} else if (g_str_equal(key, "PrimaryContexts") == TRUE) {
			const char *path;

			path = connman_device_get_string(device, "Path");
			contexts = value;
			add_default_context(&contexts, path,
					CONTEXT_NAME, CONTEXT_TYPE);
		} else if (g_str_equal(key, "Powered") == TRUE) {
			dbus_bool_t powered;

			dbus_message_iter_get_basic(&value, &powered);

			connman_device_set_powered(device, powered);
		}

		dbus_message_iter_next(&dict);
	}

	if (attached == TRUE)
		add_networks(device, &contexts);

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static void check_networks(struct modem_data *modem)
{
	char const *path = modem->path;

	DBG("modem %p path %s", modem, path);

	call_ofono(path, OFONO_GPRS_INTERFACE, GET_PROPERTIES,
			check_networks_reply, g_strdup(path), g_free,
			DBUS_TYPE_INVALID);
}

static void add_device(const char *path, const char *imsi,
				const char *mcc, const char *mnc)
{
	struct modem_data *modem;
	struct connman_device *device;

	DBG("path %s imsi %s", path, imsi);

	if (path == NULL)
		return;

	if (imsi == NULL)
		return;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return;

	device = connman_device_create(imsi, CONNMAN_DEVICE_TYPE_CELLULAR);
	if (device == NULL)
		return;

	connman_device_set_ident(device, imsi);

	connman_device_set_mode(device, CONNMAN_DEVICE_MODE_NETWORK_MULTIPLE);

	connman_device_set_string(device, "Path", path);
	if (mcc != NULL)
		connman_device_set_string(device, "MCC", mcc);
	if (mnc != NULL)
		connman_device_set_string(device, "MNC", mnc);

	if (connman_device_register(device) < 0) {
		connman_device_unref(device);
		return;
	}

	modem->device = device;

	check_networks(modem);
}

static void sim_properties_reply(DBusPendingCall *call, void *user_data)
{
	const char *path = user_data;
	const char *imsi;
	char *mcc = NULL;
	char *mnc = NULL;
	/* If MobileNetworkCodeLength is not provided, mnc_length is 0 */
	unsigned char mnc_length = 0;
	DBusMessage *reply;
	DBusMessageIter array, dict;

	DBG("path %s", path);

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "SubscriberIdentity") == TRUE)
			dbus_message_iter_get_basic(&value, &imsi);
		/*
		 * 'MobileNetworkCodeLength' is deprecated since version 0.20, but
		 * keep it here for backward compatibility reasons.
		 */
		else if (g_str_equal(key, "MobileNetworkCodeLength") == TRUE)
			dbus_message_iter_get_basic(&value,
						(void *) &mnc_length);
		else if (g_str_equal(key, "MobileCountryCode") == TRUE)
			dbus_message_iter_get_basic(&value,
						(void *) &mcc);
		else if (g_str_equal(key, "MobileNetworkCode") == TRUE)
			dbus_message_iter_get_basic(&value,
						(void *) &mnc);

		dbus_message_iter_next(&dict);
	}

	if (mnc_length == 2 || mnc_length == 3) {
		mcc = g_strndup(imsi, 3);
		mnc = g_strndup(imsi + 3, mnc_length);
	}

	add_device(path, imsi, mcc, mnc);

	if (mnc_length == 2 || mnc_length == 3) {
		g_free(mcc);
		g_free(mnc);
	}

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static void get_imsi(const char *path)
{
	DBG("path %s", path);

	call_ofono(path, OFONO_SIM_INTERFACE, GET_PROPERTIES,
			sim_properties_reply, g_strdup(path), g_free,
			DBUS_TYPE_INVALID);
}

static int modem_change_powered(const char *path, dbus_bool_t powered)
{
	DBG("path %s powered %d", path, powered);

	return set_property(path, OFONO_MODEM_INTERFACE, "Powered",
				DBUS_TYPE_BOOLEAN, &powered,
				NULL, NULL, NULL);
}

static struct modem_data *add_modem(const char *path)
{
	struct modem_data *modem;

	DBG("path %s", path);

	if (path == NULL)
		return NULL;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem != NULL) {
		modem->available = TRUE;

		return modem;
	}

	modem = g_try_new0(struct modem_data, 1);
	if (modem == NULL)
		return NULL;

	modem->path = g_strdup(path);
	modem->device = NULL;
	modem->available = TRUE;

	g_hash_table_insert(modem_hash, g_strdup(path), modem);

	return modem;
}

static gboolean modem_has_gprs(DBusMessageIter *array)
{
	DBusMessageIter entry;

	dbus_message_iter_recurse(array, &entry);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
		const char *interface;

		dbus_message_iter_get_basic(&entry, &interface);

		if (g_strcmp0(OFONO_GPRS_INTERFACE, interface) == 0)
			return TRUE;

		dbus_message_iter_next(&entry);
	}

	return FALSE;
}

static void modem_properties_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter array, dict;
	const char *path = user_data;
	dbus_bool_t powered = FALSE;
	gboolean has_gprs = FALSE;
	struct modem_data *new_modem;

	DBG("path %s", path);

	reply = dbus_pending_call_steal_reply(call);

	if (g_hash_table_lookup(modem_hash, path))
		goto done;

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("Modem.GetProperties(%s) %s %s",
				path, error.name, error.message);
		dbus_error_free(&error);
		goto done;
	}

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Powered") == TRUE)
			dbus_message_iter_get_basic(&value, &powered);
		else if (g_str_equal(key, "Interfaces") == TRUE)
			has_gprs = modem_has_gprs(&value);

		dbus_message_iter_next(&dict);
	}

	new_modem = add_modem(path);
	if (new_modem == NULL)
		goto done;

	if (!powered)
		modem_change_powered(path, TRUE);

	if (has_gprs)
		get_imsi(path);

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static void get_modem_properties(const char *path)
{
	DBG("path %s", path);

	call_ofono(path, OFONO_MODEM_INTERFACE, GET_PROPERTIES,
			modem_properties_reply, g_strdup(path), g_free,
			DBUS_TYPE_INVALID);
}

static void mask_unavailable(gpointer key, gpointer value, gpointer user_data)
{
	struct modem_data *modem = value;

	modem->available = FALSE;
}

static void modems_set_unavailable()
{
	g_hash_table_foreach(modem_hash, mask_unavailable, NULL);
}

static void cleanup_modem(gpointer key, gpointer value, gpointer user_data)
{
	struct modem_data *modem = value;

	if (modem->available == FALSE)
		g_hash_table_remove(modem_hash, key);
}

static void cleanup_modems()
{
	g_hash_table_foreach(modem_hash, cleanup_modem, NULL);
}

static void update_modems(DBusMessageIter *array)
{
	DBusMessageIter entry;

	DBG("");

	dbus_message_iter_recurse(array, &entry);

	modems_set_unavailable();

	while (dbus_message_iter_get_arg_type(&entry) ==
					DBUS_TYPE_OBJECT_PATH) {
		const char *path;
		struct modem_data *modem;

		dbus_message_iter_get_basic(&entry, &path);

		modem = g_hash_table_lookup(modem_hash, path);

		if (modem)
			modem->available = TRUE;
		else
			get_modem_properties(path);

		dbus_message_iter_next(&entry);
	}

	cleanup_modems();
}

static void manager_properties_reply(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter array, dict;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("ModemManager.GetProperties() %s %s",
				error.name, error.message);
		dbus_error_free(&error);
		goto done;
	}

	if (dbus_message_iter_init(reply, &array) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
		goto done;

	dbus_message_iter_recurse(&array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Modems") == TRUE) {
			update_modems(&value);
			break;
		}

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);
}

static void modem_remove_device(struct modem_data *modem)
{
	if (modem->device == NULL)
		return;

	connman_device_unregister(modem->device);
	connman_device_unref(modem->device);

	modem->device = NULL;
}

static void remove_modem(gpointer data)
{
	struct modem_data *modem = data;

	g_free(modem->path);

	modem_remove_device(modem);

	g_free(modem);
}

static void ofono_connect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);

	modem_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, remove_modem);

	call_ofono("/", OFONO_MANAGER_INTERFACE, GET_PROPERTIES,
			manager_properties_reply, NULL, NULL,
			DBUS_TYPE_INVALID);
}

static void ofono_disconnect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);

	if (modem_hash == NULL)
		return;

	g_hash_table_destroy(modem_hash);

	modem_hash = NULL;
}

static gboolean modem_changed(DBusConnection *connection, DBusMessage *message,
				void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct modem_data *modem;
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return TRUE;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Powered") == TRUE) {
		dbus_bool_t powered;

		dbus_message_iter_get_basic(&value, &powered);
		if (powered == TRUE)
			return TRUE;

		modem_remove_device(modem);
	} else if (g_str_equal(key, "Interfaces") == TRUE) {
		if (modem_has_gprs(&value) == TRUE) {
			if (modem->device == NULL)
				get_imsi(modem->path);
		} else if (modem->device != NULL)
			modem_remove_device(modem);
	}

	return TRUE;
}

static gboolean gprs_changed(DBusConnection *connection, DBusMessage *message,
				void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct modem_data *modem;
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return TRUE;

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Attached") == TRUE) {
		dbus_bool_t attached;

		dbus_message_iter_get_basic(&value, &attached);

		DBG("Attached %d", attached);

		if (attached == TRUE)
			check_networks(modem);
		else if (modem->device != NULL)
			connman_device_remove_all_networks(modem->device);

	} else if (g_str_equal(key, "PrimaryContexts") == TRUE) {
		check_networks(modem);
	} else if (g_str_equal(key, "Powered") == TRUE) {
		dbus_bool_t powered;

		if (modem->device == NULL)
			return TRUE;

		dbus_message_iter_get_basic(&value, &powered);
		connman_device_set_powered(modem->device, powered);
	}

	return TRUE;
}

static gboolean manager_changed(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	const char *path = dbus_message_get_path(message);
	DBusMessageIter iter, value;
	const char *key;

	DBG("path %s", path);

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Modems") == TRUE)
		update_modems(&value);

	return TRUE;
}

static void get_dns(DBusMessageIter *array, struct connman_element *parent)
{
	DBusMessageIter entry;
	gchar *nameserver = NULL, *nameserver_old = NULL;

	DBG("");

	dbus_message_iter_recurse(array, &entry);

	while (dbus_message_iter_get_arg_type(&entry) == DBUS_TYPE_STRING) {
		const char *dns;

		dbus_message_iter_get_basic(&entry, &dns);

		DBG("dns %s", dns);

		if (nameserver == NULL) {

			nameserver = g_strdup(dns);
		} else {

			nameserver_old = nameserver;
			nameserver = g_strdup_printf("%s %s",
						nameserver_old, dns);
			g_free(nameserver_old);
		}

		dbus_message_iter_next(&entry);
	}

	parent->ipv4.nameserver = nameserver;
}

static void update_settings(DBusMessageIter *array,
			struct connman_element *parent)
{
	DBusMessageIter dict;
	const char *interface = NULL;

	DBG("");

	if (dbus_message_iter_get_arg_type(array) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(array, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, value;
		const char *key;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &value);

		if (g_str_equal(key, "Interface") == TRUE) {
			int index;

			dbus_message_iter_get_basic(&value, &interface);

			DBG("interface %s", interface);

			index = connman_inet_ifindex(interface);
			if (index >= 0) {
				connman_network_set_index(
					pending_network, index);
			} else {
				connman_error("Can not find interface %s",
								interface);
				break;
			}
		} else if (g_str_equal(key, "Method") == TRUE) {
			const char *method;

			dbus_message_iter_get_basic(&value, &method);
			if (g_strcmp0(method, "static") == 0) {

				parent->ipv4.method =
					CONNMAN_IPCONFIG_METHOD_FIXED;
			} else if (g_strcmp0(method, "dhcp") == 0) {

				parent->ipv4.method =
					CONNMAN_IPCONFIG_METHOD_DHCP;
				break;
			}
		} else if (g_str_equal(key, "Address") == TRUE) {
			const char *address;

			dbus_message_iter_get_basic(&value, &address);

			DBG("address %s", address);

			parent->ipv4.address = g_strdup(address);
		} else if (g_str_equal(key, "Netmask") == TRUE) {
			const char *netmask;

			dbus_message_iter_get_basic(&value, &netmask);

			DBG("netmask %s", netmask);

			parent->ipv4.netmask = g_strdup(netmask);
		} else if (g_str_equal(key, "DomainNameServers") == TRUE) {

			get_dns(&value, parent);
		} else if (g_str_equal(key, "Gateway") == TRUE) {
			const char *gateway;

			dbus_message_iter_get_basic(&value, &gateway);

			DBG("gateway %s", gateway);

			parent->ipv4.gateway = g_strdup(gateway);
		}

		dbus_message_iter_next(&dict);
	}

	/* deactive, oFono send NULL inteface before deactive signal */
	if (interface == NULL)
		connman_network_set_index(pending_network, -1);
}

static void cleanup_ipconfig(struct connman_element *parent)
{
	g_free(parent->ipv4.address);
	parent->ipv4.address = NULL;

	g_free(parent->ipv4.netmask);
	parent->ipv4.netmask = NULL;

	g_free(parent->ipv4.nameserver);
	parent->ipv4.nameserver = NULL;

	g_free(parent->ipv4.gateway);
	parent->ipv4.gateway = NULL;

	parent->ipv4.method = CONNMAN_IPCONFIG_METHOD_UNKNOWN;
}

static int static_network_set_connected(
		struct connman_network *pending_network,
				struct connman_element *parent,
					connman_bool_t connected)
{
	if (connected == FALSE)
		cleanup_ipconfig(parent);

	connman_network_set_connected(pending_network, connected);

	return 0;
}

static gboolean pri_context_changed(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	const char *path = dbus_message_get_path(message);
	struct connman_element *parent;
	const char *pending_path;
	DBusMessageIter iter, value;
	const char *key;

	DBG("pending_network %p, path %s", pending_network, path);

	if (pending_network == NULL)
		return TRUE;

	pending_path = connman_network_get_string(pending_network, "Path");
	if (g_strcmp0(pending_path, path) != 0)
		return TRUE;

	parent = connman_network_get_element(pending_network);

	if (dbus_message_iter_init(message, &iter) == FALSE)
		return TRUE;

	dbus_message_iter_get_basic(&iter, &key);

	dbus_message_iter_next(&iter);
	dbus_message_iter_recurse(&iter, &value);

	if (g_str_equal(key, "Settings") == TRUE) {

		update_settings(&value, parent);
	} else if (g_str_equal(key, "Active") == TRUE) {
		dbus_bool_t active;

		dbus_message_iter_get_basic(&value, &active);

		switch (parent->ipv4.method) {
		case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
		case CONNMAN_IPCONFIG_METHOD_OFF:
		case CONNMAN_IPCONFIG_METHOD_MANUAL:
			break;
		case CONNMAN_IPCONFIG_METHOD_FIXED:
			connman_network_set_method(pending_network,
						CONNMAN_IPCONFIG_METHOD_FIXED);

			if (static_network_set_connected(
					pending_network, parent, active) < 0)
				set_network_active(pending_network, FALSE);
			break;
		case CONNMAN_IPCONFIG_METHOD_DHCP:
			connman_network_set_method(pending_network,
						CONNMAN_IPCONFIG_METHOD_DHCP);
			connman_network_set_connected(pending_network, active);
			break;
		}

		pending_network = NULL;
	}

	return TRUE;
}

static guint watch;
static guint gprs_watch;
static guint modem_watch;
static guint manager_watch;
static guint context_watch;

static int ofono_init(void)
{
	int err;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	watch = g_dbus_add_service_watch(connection, OFONO_SERVICE,
			ofono_connect, ofono_disconnect, NULL, NULL);

	gprs_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_GPRS_INTERFACE,
						PROPERTY_CHANGED,
						gprs_changed,
						NULL, NULL);

	modem_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_MODEM_INTERFACE,
						PROPERTY_CHANGED,
						modem_changed,
						NULL, NULL);

	manager_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_MANAGER_INTERFACE,
						PROPERTY_CHANGED,
						manager_changed,
						NULL, NULL);

	context_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						OFONO_PRI_CONTEXT_INTERFACE,
						PROPERTY_CHANGED,
						pri_context_changed,
						NULL, NULL);

	if (watch == 0 || gprs_watch == 0 || modem_watch == 0 ||
			manager_watch == 0 || context_watch == 0) {
		err = -EIO;
		goto remove;
	}

	err = connman_network_driver_register(&network_driver);
	if (err < 0)
		goto remove;

	err = connman_device_driver_register(&modem_driver);
	if (err < 0) {
		connman_network_driver_unregister(&network_driver);
		goto remove;
	}

	return 0;

remove:
	g_dbus_remove_watch(connection, watch);
	g_dbus_remove_watch(connection, gprs_watch);
	g_dbus_remove_watch(connection, modem_watch);
	g_dbus_remove_watch(connection, manager_watch);
	g_dbus_remove_watch(connection, context_watch);

	dbus_connection_unref(connection);

	return err;
}

static void ofono_exit(void)
{
	g_dbus_remove_watch(connection, watch);
	g_dbus_remove_watch(connection, gprs_watch);
	g_dbus_remove_watch(connection, modem_watch);
	g_dbus_remove_watch(connection, manager_watch);
	g_dbus_remove_watch(connection, context_watch);

	ofono_disconnect(connection, NULL);

	connman_device_driver_unregister(&modem_driver);
	connman_network_driver_unregister(&network_driver);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(ofono, "oFono telephony plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, ofono_init, ofono_exit)
