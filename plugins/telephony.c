/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2011-2013  Samsung Electronics Co., Ltd. All rights reserved.
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
#include <stdlib.h>

#include <gdbus.h>
#include <string.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/device.h>
#include <connman/network.h>
#include <connman/ipconfig.h>
#include <connman/dbus.h>
#include <connman/inet.h>
#include <connman/technology.h>
#include <connman/log.h>

#define PS_DBUS_SERVICE				"com.tcore.ps"

#define PS_MASTER_INTERFACE		PS_DBUS_SERVICE ".master"
#define PS_MODEM_INTERFACE		PS_DBUS_SERVICE ".modem"
#define PS_SERVICE_INTERFACE		PS_DBUS_SERVICE ".service"
#define PS_CONTEXT_INTERFACE		PS_DBUS_SERVICE ".context"

/* methods */
#define GET_MODEMS			"GetModems"
#define GET_SERVICES			"GetServices"
#define GET_CONTEXTS			"GetContexts"
#define ACTIVATE_CONTEXT		"Activate"
#define DEACTIVATE_CONTEXT		"Deactivate"
#define GET_PROPERTIES			"GetProperties"
#define SET_PROPERTY			"SetProperties"

/* signals */
#define MODEM_ADDED			"ModemAdded"
#define MODEM_REMOVED			"ModemRemoved"
#define SERVICE_ADDED			"ServiceAdded"
#define SERVICE_REMOVED			"ServiceRemoved"
#define CONTEXT_ADDED			"ContextAdded"
#define CONTEXT_REMOVED			"ContextRemoved"
#define PROPERTY_CHANGED		"PropertyChanged"

#define TIMEOUT 40000

#define STRING2BOOL(a)	((g_str_equal(a, "TRUE")) ?  (TRUE):(FALSE))

static DBusConnection *connection;
static GHashTable	*modem_hash;
static GHashTable	*service_hash;
static GHashTable	*network_hash;

struct telephony_service {
	char *path;

	gpointer p_modem;
	char *act;
	gboolean roaming; /* global roaming state */
	gboolean ps_attached; /* packet service is available */
};

struct telephony_modem {
	char *path;

	char *operator;
	gboolean powered;
	gboolean sim_init;
	gboolean flight_mode;
	gboolean data_allowed;
	gboolean roaming_allowed;

	struct connman_device *device;
	struct telephony_service *s_service;
};

struct telephony_network {
	char *path;
	struct connman_network *network;

	enum connman_ipconfig_method ipv4_method;
	struct connman_ipaddress *ipv4_address;

	enum connman_ipconfig_method ipv6_method;
	struct connman_ipaddress *ipv6_address;
};

/* function prototype */
static void telephony_connect(DBusConnection *connection, void *user_data);
static void telephony_disconnect(DBusConnection *connection, void *user_data);
static void __remove_modem(gpointer data);
static void __remove_service(gpointer data);
static void __remove_network(gpointer data);

static int __modem_probe(struct connman_device *device);
static void __modem_remove(struct connman_device *device);
static int __modem_enable(struct connman_device *device);
static int __modem_disable(struct connman_device *device);

static int __network_probe(struct connman_network *network);
static void __network_remove(struct connman_network *network);
static int __network_connect(struct connman_network *network);
static int __network_disconnect(struct connman_network *network);


/* dbus request and reply */
static int __dbus_request(const char *path, const char *interface,
			const char *method,
			DBusPendingCallNotifyFunction notify, void *user_data,
			DBusFreeFunction free_function, int type, ...);

static int __request_get_modems(void);
static void __response_get_modems(DBusPendingCall *call, void *user_data);
static int __request_get_services(const char *path);
static void __response_get_services(DBusPendingCall *call, void *user_data);
static int __request_get_contexts(struct telephony_modem *modem);
static void __response_get_contexts(DBusPendingCall *call, void *user_data);
static int __request_network_activate(struct connman_network *network);
static void __response_network_activate(DBusPendingCall *call, void *user_data);
static int __request_network_deactivate(struct connman_network *network);

/* telephony internal function */
static void __add_modem(const char *path, DBusMessageIter *prop);
static void __add_service(struct telephony_modem *modem,
			const char *service_path, DBusMessageIter *prop);
static void __add_connman_device(const char *modem_path, const char *operator);
static void __remove_connman_device(struct telephony_modem *modem);
static void __remove_connman_networks(struct connman_device *device);
static void __set_device_powered(struct telephony_modem *modem,
					gboolean powered);
static int __check_device_powered(const char *path, gboolean online);
static gboolean __check_network_available(struct connman_network *network);
static void __create_service(struct connman_network *network);
static int __add_context(struct connman_device *device, const char *path,
							DBusMessageIter *prop);
static gboolean __set_network_ipconfig(struct telephony_network *network,
							DBusMessageIter *dict);
static void __set_network_connected(struct telephony_network *network,
							gboolean connected);
static char *__get_ident(const char *path);

/* signal handler */
static gboolean __changed_modem(DBusConnection *connection,
				DBusMessage *message, void *user_data);
static gboolean __added_modem(DBusConnection *connection,
				DBusMessage *message, void *user_data);
static gboolean __removed_modem(DBusConnection *connection,
				DBusMessage *message, void *user_data);
static gboolean __changed_service(DBusConnection *connection,
				DBusMessage *message, void *user_data);
static gboolean __added_service(DBusConnection *connection,
				DBusMessage *message, void *user_data);
static gboolean __removed_service(DBusConnection *connection,
				DBusMessage *message, void *user_data);
static gboolean __changed_context(DBusConnection *connection,
				DBusMessage *message, void *user_data);
static gboolean __added_context(DBusConnection *connection,
				DBusMessage *message, void *user_data);
static gboolean __removed_context(DBusConnection *connection,
				DBusMessage *message, void *user_data);

/* device driver */
static struct connman_device_driver modem_driver = {
	.name		= "device",
	.type		= CONNMAN_DEVICE_TYPE_CELLULAR,
	.probe		= __modem_probe,
	.remove		= __modem_remove,
	.enable		= __modem_enable,
	.disable	= __modem_disable,
};

/* network driver */
static struct connman_network_driver network_driver = {
	.name		= "network",
	.type		= CONNMAN_NETWORK_TYPE_CELLULAR,
	.probe		= __network_probe,
	.remove		= __network_remove,
	.connect	= __network_connect,
	.disconnect	= __network_disconnect,
};

static int tech_probe(struct connman_technology *technology)
{
	return 0;
}

static void tech_remove(struct connman_technology *technology)
{
}

static struct connman_technology_driver tech_driver = {
	.name		= "cellular",
	.type		= CONNMAN_SERVICE_TYPE_CELLULAR,
	.probe		= tech_probe,
	.remove		= tech_remove,
};

/* local function */
static void telephony_connect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);
	modem_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, __remove_modem);
	service_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, __remove_service);
	network_hash = g_hash_table_new_full(g_str_hash, g_str_equal,
						g_free, __remove_network);
	__request_get_modems();
	return;
}

static void telephony_disconnect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);

	if (modem_hash != NULL) {
		g_hash_table_destroy(modem_hash);
		modem_hash = NULL;
	}

	if (network_hash != NULL) {
		g_hash_table_destroy(network_hash);
		network_hash = NULL;
	}

	return;
}

static void __remove_modem(gpointer data)
{
	struct telephony_modem *modem = data;

	__remove_connman_device(modem);

	g_free(modem->path);
	g_free(modem->operator);
	g_free(modem);
}

static void __remove_service(gpointer data)
{
	struct telephony_service *service = data;

	g_free(service->path);
	g_free(service->act);
	g_free(service);
}

static void __remove_network(gpointer data)
{
	struct telephony_network *info = data;
	struct connman_device *device;

	device = connman_network_get_device(info->network);
	if (device != NULL)
		connman_device_remove_network(device, info->network);

	connman_network_unref(info->network);

	g_free(info->path);
	connman_ipaddress_free(info->ipv4_address);
	connman_ipaddress_free(info->ipv6_address);
	g_free(info);
}

static int __modem_probe(struct connman_device *device)
{
	DBG("device %p", device);
	return 0;
}

static void __modem_remove(struct connman_device *device)
{
	DBG("device %p", device);
}

static int __modem_enable(struct connman_device *device)
{
	const char *path = connman_device_get_string(device, "Path");
	DBG("device %p, path, %s", device, path);

	return __check_device_powered(path, TRUE);
}

static int __modem_disable(struct connman_device *device)
{
	const char *path = connman_device_get_string(device, "Path");
	DBG("device %p, path, %s", device, path);

	return __check_device_powered(path, FALSE);
}

static int __network_probe(struct connman_network *network)
{
	DBG("network_prove network(%p)", network);
	return 0;
}

static int __network_connect(struct connman_network *network)
{
	struct connman_device *device;
	struct telephony_modem *modem;

	DBG("network %p", network);

	device = connman_network_get_device(network);
	if (device == NULL)
		return -ENODEV;

	modem = connman_device_get_data(device);
	if (modem == NULL)
		return -ENODEV;

	if (modem->powered == FALSE)
		return -ENOLINK;

/*
	if (modem->online == FALSE)
		return -ENOLINK;

	if (modem->roaming_allowed == FALSE && modem->roaming == TRUE)
		return -ENOLINK;
*/

	return __request_network_activate(network);
}

static int __network_disconnect(struct connman_network *network)
{
	DBG("network %p", network);

	if (connman_network_get_index(network) < 0)
		return -ENOTCONN;

	connman_network_set_associating(network, FALSE);

	return __request_network_deactivate(network);
}

static void __network_remove(struct connman_network *network)
{
	char const *path = connman_network_get_string(network, "Path");
	DBG("network %p path %s", network, path);

	g_hash_table_remove(network_hash, path);
	return;
}

static int __dbus_request(const char *path, const char *interface,
			const char *method,
			DBusPendingCallNotifyFunction notify, void *user_data,
			DBusFreeFunction free_function, int type, ...)
{
	DBG("telephony request");

	DBusMessage *message;
	DBusPendingCall *call;
	dbus_bool_t ok;
	va_list va;

	DBG("path %s %s.%s", path, interface, method);

	if (path == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(PS_DBUS_SERVICE, path,
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

static int __request_get_modems(void)
{
	DBG("request get modem");
	/* call connect master */
	return __dbus_request("/", PS_MASTER_INTERFACE, GET_MODEMS,
			__response_get_modems, NULL, NULL, DBUS_TYPE_INVALID);
}

static void __response_get_modems(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter args, dict;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("GetModems() %s %s", error.name, error.message);
		dbus_error_free(&error);
		goto done;
	}

	DBG("message signature (%s)", dbus_message_get_signature(reply));

	if (dbus_message_iter_init(reply, &args) == FALSE)
		goto done;

	dbus_message_iter_recurse(&args, &dict);

	/* DBG("message type (%d) dic(%d)",
	 *	dbus_message_iter_get_arg_type(&dict), DBUS_TYPE_DICT_ENTRY);
	 */

	while (dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry, property;
		const char *modem_path;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &modem_path);
		DBG("modem path (%s)", modem_path);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &property);

		__add_modem(modem_path, &property);

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
	return;
}

static int __request_get_services(const char *path)
{
	DBG("request get service");
	return __dbus_request(path, PS_MODEM_INTERFACE, GET_SERVICES,
				__response_get_services, g_strdup(path),
				g_free, DBUS_TYPE_INVALID);
}

static void __response_get_services(DBusPendingCall *call, void *user_data)
{
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter args, dict;

	const char *path = user_data;
	struct telephony_modem *modem;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return;
	if (modem->device == NULL)
		return;

	DBG("");

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("GetServices() %s %s", error.name, error.message);
		dbus_error_free(&error);
		goto done;
	}

	DBG("message signature (%s)", dbus_message_get_signature(reply));

	if (dbus_message_iter_init(reply, &args) == FALSE)
		goto done;

	dbus_message_iter_recurse(&args, &dict);

	/* DBG("message type (%d) dic(%d)",
	 *	 dbus_message_iter_get_arg_type(&dict), DBUS_TYPE_DICT_ENTRY);
	 */

	while (dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry, property;
		const char *service_path;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &service_path);
		DBG("service path (%s)", service_path);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &property);

		__add_service(modem, service_path, &property);

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
	return;
}

static int __request_get_contexts(struct telephony_modem *modem)
{
	DBG("request get contexts");
	return __dbus_request(modem->s_service->path,
				PS_SERVICE_INTERFACE, GET_CONTEXTS,
				__response_get_contexts, g_strdup(modem->path),
				g_free, DBUS_TYPE_INVALID);
}

static void __response_get_contexts(DBusPendingCall *call, void *user_data)
{
	DBusError error;
	DBusMessage *reply;
	DBusMessageIter args, dict;

	const char *path = user_data;
	struct telephony_modem *modem;

	DBG("");

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return;
	if (modem->s_service == NULL)
			return;
	if (modem->device == NULL)
		return;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("GetContexts() %s %s", error.name, error.message);
		dbus_error_free(&error);
		goto done;
	}

	DBG("message signature (%s)", dbus_message_get_signature(reply));

	if (dbus_message_iter_init(reply, &args) == FALSE)
		goto done;

	dbus_message_iter_recurse(&args, &dict);

	while (dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry, property;
		const char *context_path;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &context_path);
		DBG("context path (%s)", context_path);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &property);

		__add_context(modem->device, context_path, &property);

		dbus_message_iter_next(&dict);
	}

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
	return;
}

static int __request_network_activate(struct connman_network *network)
{
	DBG("request network activate");

	const char *path = connman_network_get_string(network, "Path");
	DBG("network %p, path %s", network, path);

	return __dbus_request(path, PS_CONTEXT_INTERFACE, ACTIVATE_CONTEXT,
			__response_network_activate,
			g_strdup(path), NULL, DBUS_TYPE_INVALID);
}

static void __response_network_activate(DBusPendingCall *call, void *user_data)
{
	DBG("network activation response");

	DBusError error;
	DBusMessage *reply;

	struct telephony_network *info;
	const char *path = user_data;

	info = g_hash_table_lookup(network_hash, path);
	reply = dbus_pending_call_steal_reply(call);

	if (info == NULL)
		goto done;

	if (!__check_network_available(info->network)) {
		g_hash_table_remove(network_hash, path);
		goto done;
	}

	dbus_error_init(&error);
	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("connection activate() %s %s",
					error.name, error.message);

		if (connman_network_get_index(info->network) < 0)
			connman_network_set_error(info->network,
					CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL);

		dbus_error_free(&error);
		goto done;
	}

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
	return;
}

static int __request_network_deactivate(struct connman_network *network)
{
	DBG("request network deactivate");

	const char *path = connman_network_get_string(network, "Path");
	DBG("network %p, path %s", network, path);

	return __dbus_request(path, PS_CONTEXT_INTERFACE, DEACTIVATE_CONTEXT,
		NULL, NULL, NULL, DBUS_TYPE_INVALID);
}

static void __add_modem(const char *path, DBusMessageIter *prop)
{
	struct telephony_modem *modem;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem != NULL)
		return;

	modem = (struct telephony_modem *)malloc(
					sizeof(struct telephony_modem));
	memset(modem, 0, sizeof(struct telephony_modem));

	modem->path = g_strdup(path);
	modem->device = NULL;
	modem->s_service = NULL;

	g_hash_table_insert(modem_hash, g_strdup(path), modem);

	while (dbus_message_iter_get_arg_type(prop) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key, *tmp;

		dbus_message_iter_recurse(prop, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &tmp);

		DBG("key (%s) value(%s)", key, tmp);

		if (g_str_equal(key, "powered") == TRUE) {
			modem->powered = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "operator") == TRUE) {
			modem->operator = g_strdup(tmp);
		} else if (g_str_equal(key, "sim_init") == TRUE) {
			modem->sim_init = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "flight_mode") == TRUE) {
			modem->flight_mode = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "roaming_allowed") == TRUE) {
			modem->roaming_allowed = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "data_allowed") == TRUE) {
			modem->data_allowed = STRING2BOOL(tmp);
		}
		dbus_message_iter_next(prop);
	}

	__add_connman_device(path, modem->operator);
	__set_device_powered(modem, modem->powered);

	if (modem->powered != TRUE) {
		DBG("modem is not powered");
		return;
	}

	__request_get_services(modem->path);

	return;
}

static void __add_service(struct telephony_modem *modem,
				const char *service_path, DBusMessageIter *prop)
{
	struct telephony_service *service;

	if (modem->s_service != NULL)
		return;

	service = (struct telephony_service *)malloc(
					sizeof(struct telephony_service));
	memset(service, 0, sizeof(struct telephony_service));

	service->path = g_strdup(service_path);
	service->p_modem = modem;
	g_hash_table_insert(service_hash, g_strdup(service_path), service);

	while (dbus_message_iter_get_arg_type(prop) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key, *tmp;

		dbus_message_iter_recurse(prop, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &tmp);

		DBG("key (%s) value(%s)", key, tmp);

		if (g_str_equal(key, "roaming") == TRUE) {
			service->roaming = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "act") == TRUE) {
			service->act = g_strdup(tmp);
		} else if (g_str_equal(key, "ps_attached") == TRUE) {
			service->ps_attached = STRING2BOOL(tmp);
		}

		dbus_message_iter_next(prop);
	}

	modem->s_service = service;
	__request_get_contexts(modem);

	return;
}

static void __add_connman_device(const char *modem_path, const char *operator)
{
	struct telephony_modem *modem;
	struct connman_device *device;

	DBG("path %s operator %s", modem_path, operator);

	if (modem_path == NULL)
		return;

	if (operator == NULL)
		return;

	modem = g_hash_table_lookup(modem_hash, modem_path);
	if (modem == NULL)
		return;

	if (modem->device) {
		if (!g_strcmp0(operator,
				connman_device_get_ident(modem->device)))
			return;

		__remove_connman_device(modem);
	}

	if (strlen(operator) == 0)
		return;

	device = connman_device_create(operator, CONNMAN_DEVICE_TYPE_CELLULAR);
	if (device == NULL)
		return;

	connman_device_set_ident(device, operator);
	connman_device_set_string(device, "Path", modem_path);
	connman_device_set_data(device, modem);

	if (connman_device_register(device) < 0) {
		connman_error("Failed to register cellular device");
		connman_device_unref(device);
		return;
	}

	modem->device = device;

	return;
}

static void __remove_connman_device(struct telephony_modem *modem)
{
	DBG("modem %p path %s device %p", modem, modem->path, modem->device);

	if (modem->device == NULL)
		return;

	__remove_connman_networks(modem->device);

	connman_device_unregister(modem->device);
	connman_device_unref(modem->device);

	modem->device = NULL;

	return;
}

static void __remove_connman_networks(struct connman_device *device)
{
	GHashTableIter iter;
	gpointer key, value;
	GSList *info_list = NULL;
	GSList *list;

	if (network_hash == NULL)
		return;

	g_hash_table_iter_init(&iter, network_hash);

	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		struct telephony_network *info = value;

		if (connman_network_get_device(info->network) != device)
			continue;

		info_list = g_slist_append(info_list, info);
	}

	for (list = info_list; list != NULL; list = list->next) {
		struct telephony_network *info = list->data;
		connman_device_remove_network(device, info->network);
	}

	g_slist_free(info_list);
}

static void __set_device_powered(struct telephony_modem *modem,
					gboolean powered)
{
	DBG("set modem(%s) powered(%d)", modem->path, powered);

	if (modem->device)
		connman_device_set_powered(modem->device, powered);

	return;
}

static int __check_device_powered(const char *path, gboolean powered)
{
	struct telephony_modem *modem = g_hash_table_lookup(modem_hash, path);

	if (modem == NULL)
		return -ENODEV;

	DBG("check modem (%s) powered (%d)", modem->path, modem->powered);

	if (modem->powered == powered)
		return -EALREADY;

	return 0;
}

static gboolean __check_network_available(struct connman_network *network)
{
	if (network == NULL || connman_network_get_device(network) == NULL) {
		DBG("Modem or network was removed");
		return FALSE;
	}

	return TRUE;
}

static int __add_context(struct connman_device *device, const char *path,
				DBusMessageIter *prop)
{
	char *ident;
	gboolean active = FALSE;

	struct telephony_modem *modem = connman_device_get_data(device);
	struct connman_network *network;
	struct telephony_network *info;

	DBG("modem %p device %p path %s", modem, device, path);

	ident = __get_ident(path);

	network = connman_device_get_network(device, ident);
	if (network != NULL)
		return -EALREADY;

	info = g_hash_table_lookup(network_hash, path);
	if (info != NULL) {
		DBG("path %p already exists with device %p", path,
			connman_network_get_device(info->network));

		if (connman_network_get_device(info->network))
			return -EALREADY;

		g_hash_table_remove(network_hash, path);
	}

	network = connman_network_create(ident, CONNMAN_NETWORK_TYPE_CELLULAR);
	if (network == NULL)
		return -ENOMEM;

	info = (struct telephony_network *)malloc(
					sizeof(struct telephony_network));
	if (info == NULL) {
		connman_network_unref(network);
		return -ENOMEM;
	}

	memset(info, 0, sizeof(struct telephony_network));

	info->path = g_strdup(path);

	connman_ipaddress_clear(info->ipv4_address);
	connman_ipaddress_clear(info->ipv6_address);
	info->network = network;

	connman_network_set_string(network, "Path", path);
	connman_network_set_name(network, path);

	__create_service(network);

	g_hash_table_insert(network_hash, g_strdup(path), info);

	connman_network_set_available(network, TRUE);
	connman_network_set_index(network, -1);
	connman_network_set_bool(network, "Roaming", modem->s_service->roaming);

	if (connman_device_add_network(device, network) != 0) {
		g_hash_table_remove(network_hash, path);
		return -EIO;
	}

	active = __set_network_ipconfig(info, prop);

	if (active && (connman_network_get_connecting(network) ||
				connman_network_get_associating(network)))
		__set_network_connected(info, active);

	return 0;
}

static void __create_service(struct connman_network *network)
{
	const char *path;
	char *group;

	DBG("");

	path = connman_network_get_string(network, "Path");

	group = __get_ident(path);

	connman_network_set_group(network, group);
}

static gboolean __set_network_ipconfig(struct telephony_network *network,
					DBusMessageIter *dict)
{
	DBG("set network info");

	gboolean active = FALSE;
	char *dev_name = NULL, *proxy_addr = NULL;
	char *ipv4_addr = NULL, *ipv4_gw = NULL, *ipv4_netmask = NULL,
					*ipv4_dns1 = NULL, *ipv4_dns2 = NULL;
	char *ipv6_addr = NULL, *ipv6_gw = NULL, *ipv6_netmask = NULL,
					*ipv6_dns1 = NULL, *ipv6_dns2 = NULL;
	int index;
	int dns_flag = 0;

	while (dbus_message_iter_get_arg_type(dict) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key, *tmp;

		dbus_message_iter_recurse(dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		DBG("key (%s)", key);

		if (g_str_equal(key, "dev_name") == TRUE) {
			dbus_message_iter_get_basic(&entry, &dev_name);
			DBG("dev_name (%s)", dev_name);
		} else if (g_str_equal(key, "proxy") == TRUE) {
			dbus_message_iter_get_basic(&entry, &proxy_addr);
		} else if (g_str_equal(key, "ipv4_address") == TRUE) {
			dbus_message_iter_get_basic(&entry, &ipv4_addr);
			DBG("ipv4 address (%s)", ipv4_addr);
		} else if (g_str_equal(key, "ipv4_gateway") == TRUE) {
			dbus_message_iter_get_basic(&entry, &ipv4_gw);
		} else if (g_str_equal(key, "ipv4_netmask") == TRUE) {
			dbus_message_iter_get_basic(&entry, &ipv4_netmask);
		} else if (g_str_equal(key, "ipv4_dns1") == TRUE) {
			dbus_message_iter_get_basic(&entry, &ipv4_dns1);
		} else if (g_str_equal(key, "ipv4_dns2") == TRUE) {
			dbus_message_iter_get_basic(&entry, &ipv4_dns2);
		} else if (g_str_equal(key, "ipv6_address") == TRUE) {
			dbus_message_iter_get_basic(&entry, &ipv6_addr);
			DBG("ipv6 address (%s)", ipv6_addr);
		} else if (g_str_equal(key, "ipv6_gateway") == TRUE) {
			dbus_message_iter_get_basic(&entry, &ipv6_gw);
		} else if (g_str_equal(key, "ipv6_netmask") == TRUE) {
			dbus_message_iter_get_basic(&entry, &ipv6_netmask);
		} else if (g_str_equal(key, "ipv6_dns1") == TRUE) {
			dbus_message_iter_get_basic(&entry, &ipv6_dns1);
		} else if (g_str_equal(key, "ipv6_dns2") == TRUE) {
			dbus_message_iter_get_basic(&entry, &ipv6_dns2);
		} else if (g_str_equal(key, "active") == TRUE) {
			dbus_message_iter_get_basic(&entry, &tmp);
			DBG("active (%s)", tmp);
			active = STRING2BOOL(tmp);
		}

		dbus_message_iter_next(dict);
	}

	/* interface index set */
	if (dev_name == NULL)
		dev_name = "";

	if (g_str_equal(dev_name, "")) {
		const char *ifname = NULL;
		ifname = connman_network_get_ifname(network->network);
		index = connman_inet_ifindex(ifname);
	} else
		index = connman_inet_ifindex(dev_name);

	DBG("interface %s, index %d", dev_name, index);
	connman_network_set_index(network->network, index);

	/* proxy set */
	if (proxy_addr == NULL)
		proxy_addr = "";

	DBG("proxy (%s) is set", proxy_addr);
	connman_network_set_proxy(network->network, proxy_addr);

	/* ipv4 set */
	if (ipv4_addr == NULL)
		ipv4_addr = "0.0.0.0";

	if (g_str_equal(ipv4_addr, "0.0.0.0")) {
		network->ipv4_method = CONNMAN_IPCONFIG_METHOD_OFF;
	} else {
		network->ipv4_method = CONNMAN_IPCONFIG_METHOD_FIXED;
		network->ipv4_address =
			connman_ipaddress_alloc(CONNMAN_IPCONFIG_TYPE_IPV4);
		if (network->ipv4_address == NULL)
			return FALSE;

		connman_ipaddress_set_ipv4(network->ipv4_address, ipv4_addr,
						ipv4_netmask, ipv4_gw);

		if (ipv4_dns1 == NULL)
			ipv4_dns1 = "0.0.0.0";
		if (ipv4_dns2 == NULL)
			ipv4_dns2 = "0.0.0.0";

		if (g_str_equal(ipv4_dns1, "0.0.0.0"))
			dns_flag += 1;

		if (g_str_equal(ipv4_dns2, "0.0.0.0"))
			dns_flag += 2;

		gchar *nameservers = NULL;

		switch (dns_flag) {
		case 0:
			nameservers = g_strdup_printf("%s %s", ipv4_dns1,
								ipv4_dns2);
			break;
		case 1:
			nameservers = g_strdup_printf("%s", ipv4_dns2);
			break;
		case 2:
			nameservers = g_strdup_printf("%s", ipv4_dns1);
		}

		connman_network_set_nameservers(network->network, nameservers);
		g_free(nameservers);
	}

	/* ipv6 set */
	if (ipv6_addr == NULL)
		ipv6_addr = "::";

	if (g_str_equal(ipv6_addr, "::")) {
		network->ipv6_method = CONNMAN_IPCONFIG_METHOD_OFF;
	} else {
		network->ipv6_method = CONNMAN_IPCONFIG_METHOD_FIXED;
		unsigned char prefix_length = 64;
		network->ipv6_address =
			connman_ipaddress_alloc(CONNMAN_IPCONFIG_TYPE_IPV6);
		if (network->ipv6_address == NULL)
			return FALSE;

		connman_ipaddress_set_ipv6(network->ipv6_address, ipv6_addr,
						prefix_length, ipv6_gw);

		dns_flag = 0;

		if (ipv6_dns1 == NULL)
			ipv6_dns1 = "::";
		if (ipv6_dns2 == NULL)
			ipv6_dns2 = "::";

		if (g_str_equal(ipv6_dns1, "::"))
			dns_flag += 1;

		if (g_str_equal(ipv6_dns2, "::"))
			dns_flag += 2;

		gchar *nameservers = NULL;

		switch (dns_flag) {
		case 0:
			nameservers = g_strdup_printf("%s %s", ipv6_dns1,
								ipv6_dns2);
			break;
		case 1:
			nameservers = g_strdup_printf("%s", ipv6_dns2);
			break;
		case 2:
			nameservers = g_strdup_printf("%s", ipv6_dns1);
		}

		connman_network_set_nameservers(network->network, nameservers);
		g_free(nameservers);
	}

	if (active)
		connman_network_set_associating(network->network, TRUE);

	return active;
}

static void __set_network_connected(struct telephony_network *network,
					gboolean connected)
{
	gboolean setip = FALSE;

	DBG("network %p connected %d", network, connected);

	switch (network->ipv4_method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		setip = TRUE;
		break;

	case CONNMAN_IPCONFIG_METHOD_FIXED:
		connman_network_set_ipv4_method(network->network,
							network->ipv4_method);
		connman_network_set_ipaddress(network->network,
							network->ipv4_address);
		setip = TRUE;
		break;

	case CONNMAN_IPCONFIG_METHOD_DHCP:
		connman_network_set_ipv4_method(network->network,
							network->ipv4_method);
		setip = TRUE;
		break;
	}

	switch (network->ipv6_method) {
	case CONNMAN_IPCONFIG_METHOD_UNKNOWN:
	case CONNMAN_IPCONFIG_METHOD_OFF:
	case CONNMAN_IPCONFIG_METHOD_MANUAL:
	case CONNMAN_IPCONFIG_METHOD_DHCP:
	case CONNMAN_IPCONFIG_METHOD_AUTO:
		DBG("ipv6 not supported");
		break;

	case CONNMAN_IPCONFIG_METHOD_FIXED:
		connman_network_set_ipv6_method(network->network,
							network->ipv6_method);
		connman_network_set_ipaddress(network->network,
							network->ipv6_address);
		setip = TRUE;
		break;
	}

	if (setip == TRUE)
		connman_network_set_connected(network->network, connected);

	return;
}

static char *__get_ident(const char *path)
{
	char *pos;

	if (*path != '/')
		return NULL;

	pos = strrchr(path, '/');
	if (pos == NULL)
		return NULL;

	return pos + 1;
}

static gboolean __changed_modem(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	DBG("modem changed signal");

	DBusMessageIter args, dict;
	const char *path = dbus_message_get_path(message);
	struct telephony_modem *modem;

	DBG("modem path %s", path);

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL) {
		DBG("modem object does not exists");
		return TRUE;
	}

	DBG("message signature (%s)", dbus_message_get_signature(message));

	if (dbus_message_iter_init(message, &args) == FALSE) {
		DBG("error to read message");
		return TRUE;
	}

	dbus_message_iter_recurse(&args, &dict);

	while (dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key, *tmp;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &tmp);

		DBG("key(%s), value(%s)", key, tmp);

		if (g_str_equal(key, "powered") == TRUE) {
			modem->powered = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "operator") == TRUE) {
			modem->operator = g_strdup(tmp);
		} else if (g_str_equal(key, "sim_init") == TRUE) {
			modem->sim_init = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "flight_mode") == TRUE) {
			modem->flight_mode = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "roaming_allowed") == TRUE) {
			modem->roaming_allowed = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "data_allowed") == TRUE) {
			modem->data_allowed = STRING2BOOL(tmp);
		}

		dbus_message_iter_next(&dict);
	}

	if (modem->device == NULL)
		__add_connman_device(path, modem->operator);

	__set_device_powered(modem, modem->powered);

	if (modem->powered != TRUE) {
		DBG("modem is not powered");
		return TRUE;
	}

	if (!modem->s_service) {
		__request_get_services(modem->path);
		return TRUE;
	}

	if (modem->flight_mode || !modem->data_allowed) {
		DBG("modem(%s) flight mode(%d) data allowed(%d)",
			modem->path, modem->flight_mode, modem->data_allowed);
		return TRUE;
	}

	return TRUE;
}

static gboolean __added_modem(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	DBG("modem added signal");

	const char *modem_path = NULL;
	DBusMessageIter args, dict, tmp;

	DBG("message signature (%s)", dbus_message_get_signature(message));
	if (dbus_message_iter_init(message, &args) == FALSE) {
		DBG("error to read message");
		return TRUE;
	}

	dbus_message_iter_recurse(&args, &dict);
	memcpy(&tmp, &dict, sizeof(struct DBusMessageIter));

	while (dbus_message_iter_get_arg_type(&tmp) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key, *value;

		dbus_message_iter_recurse(&tmp, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		DBG("key (%s) value(%s)", key, value);

		if (g_str_equal(key, "path") == TRUE)
			modem_path = g_strdup(value);

		dbus_message_iter_next(&tmp);
	}

	if (modem_path != NULL)
		__add_modem(modem_path, &dict);

	return TRUE;
}

static gboolean __removed_modem(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	DBG("modem removed signal");

	DBusMessageIter iter;
	const char *modem_path;

	if (dbus_message_iter_init(message, &iter) == FALSE) {
		DBG("error to read message");
		return TRUE;
	}

	dbus_message_iter_get_basic(&iter, &modem_path);
	g_hash_table_remove(modem_hash, modem_path);

	return TRUE;
}

static gboolean __changed_service(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	DBG("service changed signal");

	DBusMessageIter args, dict;
	const char *service_path = dbus_message_get_path(message);
	struct telephony_modem *modem;
	struct telephony_service *s_service;
	gboolean roaming_option = TRUE;

	DBG("service path %s", service_path);

	s_service = g_hash_table_lookup(service_hash, service_path);
	if (s_service == NULL) {
		DBG("service object does not exists");
		return TRUE;
	}

	modem = s_service->p_modem;
	if (modem == NULL) {
		DBG("modem object does not exists");
		return TRUE;
	}

	DBG("message signature (%s)", dbus_message_get_signature(message));

	if (dbus_message_iter_init(message, &args) == FALSE) {
		DBG("error to read message");
		return TRUE;
	}

	dbus_message_iter_recurse(&args, &dict);

	while (dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key, *tmp;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &tmp);

		DBG("key(%s), value(%s)", key, tmp);

		if (g_str_equal(key, "roaming") == TRUE) {
			s_service->roaming = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "act") == TRUE) {
			s_service->act = g_strdup(tmp);
		} else if (g_str_equal(key, "ps_attached") == TRUE) {
			s_service->ps_attached = STRING2BOOL(tmp);
		}

		dbus_message_iter_next(&dict);
	}

	roaming_option &= (!s_service->roaming && !modem->roaming_allowed)
				|| modem->roaming_allowed;

	return TRUE;
}


static gboolean __added_service(DBusConnection *connection,
				DBusMessage *message, void *user_data)
{
	DBG("service added signal");

	const char *path = dbus_message_get_path(message);
	const char *service_path = NULL;
	DBusMessageIter args, dict, tmp;
	struct telephony_modem *modem;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL || modem->device == NULL)
		return TRUE;

	DBG("message signature (%s)", dbus_message_get_signature(message));
	if (dbus_message_iter_init(message, &args) == FALSE) {
		DBG("error to read message");
		return TRUE;
	}

	dbus_message_iter_recurse(&args, &dict);
	memcpy(&tmp, &dict, sizeof(struct DBusMessageIter));

	while (dbus_message_iter_get_arg_type(&tmp) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key, *value;

		dbus_message_iter_recurse(&tmp, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		DBG("key (%s) value(%s)", key, value);

		if (g_str_equal(key, "path") == TRUE) {
			service_path = g_strdup(value);
		}

		dbus_message_iter_next(&tmp);
	}

	if (service_path != NULL)
		__add_service(modem, service_path, &dict);

	return TRUE;
}

static gboolean __removed_service(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	DBG("service removed signal");

	DBusMessageIter iter;
	const char *service_path;

	if (dbus_message_iter_init(message, &iter) == FALSE) {
		DBG("error to read message");
		return TRUE;
	}

	dbus_message_iter_get_basic(&iter, &service_path);
	g_hash_table_remove(service_hash, service_path);

	return TRUE;
}

static gboolean __changed_context(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	DBG("network changed signal");

	gboolean active = FALSE;
	const char *path = dbus_message_get_path(message);
	struct telephony_network *info;
	DBusMessageIter args, dict;

	DBG("path %s", path);
	info = g_hash_table_lookup(network_hash, path);
	if (info == NULL)
		return TRUE;

	if (!__check_network_available(info->network)) {
		g_hash_table_remove(network_hash, path);
		return TRUE;
	}

	if (dbus_message_iter_init(message, &args) == FALSE) {
		DBG("error to read message");
		return TRUE;
	}

	dbus_message_iter_recurse(&args, &dict);

	active = __set_network_ipconfig(info, &dict);

	if (active == FALSE)
		__set_network_connected(info, active);
	else if ((connman_network_get_connecting(info->network) ||
			connman_network_get_associating(info->network)))
		__set_network_connected(info, active);

	return TRUE;
}

static gboolean __added_context(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	DBG("network added signal");

	DBusMessageIter args, dict, tmp;
	const char *path = dbus_message_get_path(message);
	const char *network_path = NULL;
	struct telephony_service *service = NULL;
	struct telephony_modem *modem = NULL;

	service = g_hash_table_lookup(service_hash, path);
	if (service == NULL || service->p_modem == NULL)
		return TRUE;

	modem = service->p_modem;
	if (modem == NULL || modem->device == NULL)
		return TRUE;

	DBG("message signature (%s)", dbus_message_get_signature(message));
	if (dbus_message_iter_init(message, &args) == FALSE) {
		DBG("error to read message");
		return TRUE;
	}

	dbus_message_iter_recurse(&args, &dict);
	memcpy(&tmp, &dict, sizeof(struct DBusMessageIter));

	while (dbus_message_iter_get_arg_type(&tmp) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char *key, *value;

		dbus_message_iter_recurse(&tmp, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &value);

		DBG("key (%s) value(%s)", key, value);

		if (g_str_equal(key, "path") == TRUE)
			network_path = g_strdup(value);

		dbus_message_iter_next(&tmp);
	}

	if (network_path != NULL)
		__add_context(modem->device, network_path, &dict);

	return TRUE;
}

static gboolean __removed_context(DBusConnection *connection,
					DBusMessage *message, void *user_data)
{
	DBG("network removed signal");

	DBusMessageIter iter;
	const char *path = dbus_message_get_path(message);
	const char *network_path = NULL;
	struct telephony_service *service = NULL;

	service = g_hash_table_lookup(service_hash, path);
	if (service == NULL || service->p_modem == NULL)
		return TRUE;

	if (dbus_message_iter_init(message, &iter) == FALSE) {
		DBG("error to read message");
		return TRUE;
	}

	dbus_message_iter_get_basic(&iter, &network_path);
	g_hash_table_remove(network_hash, network_path);

	return TRUE;
}

/* telephony initialization */
static guint watch;
static guint modem_watch;
static guint modem_added_watch;
static guint modem_removed_watch;
static guint service_watch;
static guint service_added_watch;
static guint service_removed_watch;
static guint context_watch;
static guint context_added_watch;
static guint context_removed_watch;

static int telephony_init(void)
{
	DBG("telephony plugin");
	int err;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	/* telephony watch */
	watch = g_dbus_add_service_watch(connection, PS_DBUS_SERVICE,
					telephony_connect, telephony_disconnect,
					NULL, NULL);

	modem_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						PS_MODEM_INTERFACE,
						PROPERTY_CHANGED,
						__changed_modem, NULL, NULL);

	modem_added_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						PS_MASTER_INTERFACE,
						MODEM_ADDED, __added_modem,
						NULL, NULL);

	modem_removed_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						PS_MASTER_INTERFACE,
						MODEM_REMOVED, __removed_modem,
						NULL, NULL);

	service_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						PS_SERVICE_INTERFACE,
						PROPERTY_CHANGED,
						__changed_service,
						NULL, NULL);

	service_added_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						PS_MODEM_INTERFACE,
						SERVICE_ADDED, __added_service,
						NULL, NULL);

	service_removed_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						PS_MODEM_INTERFACE,
						SERVICE_REMOVED,
						__removed_service,
						NULL, NULL);

	context_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						PS_CONTEXT_INTERFACE,
						PROPERTY_CHANGED,
						__changed_context,
						NULL, NULL);

	context_added_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						PS_SERVICE_INTERFACE,
						CONTEXT_ADDED, __added_context,
						NULL, NULL);

	context_removed_watch = g_dbus_add_signal_watch(connection, NULL, NULL,
						PS_SERVICE_INTERFACE,
						CONTEXT_REMOVED,
						__removed_context,
						NULL, NULL);

	if (watch == 0 || modem_watch == 0 || modem_added_watch == 0
			|| modem_removed_watch == 0 || service_watch == 0
			|| service_added_watch == 0 || context_watch == 0
			|| service_removed_watch == 0
			|| context_added_watch == 0
			|| context_removed_watch == 0) {
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

	err = connman_technology_driver_register(&tech_driver);
	if (err < 0) {
		connman_device_driver_unregister(&modem_driver);
		connman_network_driver_unregister(&network_driver);
		goto remove;
	}

	return 0;

remove:
	g_dbus_remove_watch(connection, watch);
	g_dbus_remove_watch(connection, modem_watch);
	g_dbus_remove_watch(connection, modem_added_watch);
	g_dbus_remove_watch(connection, modem_removed_watch);
	g_dbus_remove_watch(connection, service_watch);
	g_dbus_remove_watch(connection, service_added_watch);
	g_dbus_remove_watch(connection, service_removed_watch);
	g_dbus_remove_watch(connection, context_watch);
	g_dbus_remove_watch(connection, context_added_watch);
	g_dbus_remove_watch(connection, context_removed_watch);

	dbus_connection_unref(connection);
	return err;
}

static void telephony_exit(void)
{
	g_dbus_remove_watch(connection, watch);
	g_dbus_remove_watch(connection, modem_watch);
	g_dbus_remove_watch(connection, modem_added_watch);
	g_dbus_remove_watch(connection, modem_removed_watch);
	g_dbus_remove_watch(connection, service_watch);
	g_dbus_remove_watch(connection, service_added_watch);
	g_dbus_remove_watch(connection, service_removed_watch);
	g_dbus_remove_watch(connection, context_watch);
	g_dbus_remove_watch(connection, context_added_watch);
	g_dbus_remove_watch(connection, context_removed_watch);

	telephony_disconnect(connection, NULL);

	connman_device_driver_unregister(&modem_driver);
	connman_network_driver_unregister(&network_driver);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(telephony, "Samsung Telephony Framework plug-in", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, telephony_init, telephony_exit)
