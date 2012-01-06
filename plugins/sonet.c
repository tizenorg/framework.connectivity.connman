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

#define SONET_SERVICE				"org.tizen.sonet"

#define SONET_MASTER_INTERFACE		SONET_SERVICE ".master"
#define SONET_MODEM_INTERFACE		SONET_SERVICE ".modem"
#define SONET_NETWORK_INTERFACE		SONET_SERVICE ".network"

//methods
#define GET_MODEMS				"GetModems"
#define GET_NETWORKS			"GetNetworks"
#define ACTIVATE_NETWORK		"Activate"
#define DEACTIVATE_NETWORK		"Deactivate"
#define GET_PROPERTIES			"GetProperties"
#define SET_PROPERTY			"SetProperties"

//signals
#define MODEM_ADDED				"ModemAdded"
#define MODEM_REMOVED			"ModemRemoved"
#define NETWORK_ADDED			"NetworkAdded"
#define NETWORK_REMOVED			"NetworkRemoved"
#define PROPERTY_CHANGED		"PropertyChanged"

#define TIMEOUT 40000

#define STRING2BOOL(a)	((g_str_equal(a, "TRUE")) ?  (TRUE):(FALSE))

static DBusConnection *connection;
static GHashTable	*modem_hash;
static GHashTable	*network_hash;

struct sonet_modem {
	char* path;
	struct connman_device *device;

	char *operator;
	gboolean powered; //modem registered (if TAPI is not ready)
	gboolean online; //flight_mode, data_allowed, sim_init

	gboolean sim_init; //sim init
	gboolean roaming; //global roaming state
	gboolean ps_attached; //packet service is available

	gboolean roaming_allowed; //roaming setting
};

struct sonet_network {
	char *path;
	struct connman_network *network;

	enum connman_ipconfig_method ipv4_method;
	struct connman_ipaddress ipv4_address;

	enum connman_ipconfig_method ipv6_method;
	struct connman_ipaddress ipv6_address;
};

// function prototype
static void sonet_connect(DBusConnection *connection, void *user_data);
static void sonet_disconnect(DBusConnection *connection, void *user_data);
static void __remove_modem(gpointer data);
static void __remove_network(gpointer data);

static int __modem_probe(struct connman_device *device);
static void __modem_remove(struct connman_device *device);
static int __modem_enable(struct connman_device *device);
static int __modem_disable(struct connman_device *device);

static int __network_probe(struct connman_network *network);
static void __network_remove(struct connman_network *network);
static int __network_connect(struct connman_network *network);
static int __network_disconnect(struct connman_network *network);


// dbus request and reply
static int __dbus_request(const char *path, const char *interface, const char *method,
			DBusPendingCallNotifyFunction notify, void *user_data,
			DBusFreeFunction free_function, int type, ...);

static int __request_get_modems(void);
static void __response_get_modems(DBusPendingCall *call, void *user_data);
static int __request_get_networks(const char* path);
static void __response_get_networks(DBusPendingCall *call, void *user_data);
static int __request_network_activate(struct connman_network *network);
static void __response_network_activate(DBusPendingCall *call, void *user_data);
static int __request_network_deactivate(struct connman_network *network);

// sonet internal function
static void __add_modem(const char *path, DBusMessageIter *prop);
static void __add_connman_device(const char* modem_path, const char* operator);
static void __remove_connman_device(struct sonet_modem *modem);
static void __remove_connman_networks(struct connman_device *device);
static void __set_device_online(struct sonet_modem *modem, gboolean online);
static int __check_device_online(const char *path, gboolean online);
static gboolean __check_network_available(struct connman_network *network);
static void __create_service(struct connman_network *network);
static int __add_network(struct connman_device *device, const char *path, DBusMessageIter *prop);
static gboolean __set_network_ipconfig(struct sonet_network *network, DBusMessageIter *dict);
static void __set_network_connected(struct sonet_network *network, gboolean connected);
static char *__get_ident(const char *path);

// signal handler
static gboolean __changed_modem(DBusConnection *connection, DBusMessage *message, void *user_data);
static gboolean __added_modem(DBusConnection *connection, DBusMessage *message, void *user_data);
static gboolean __removed_modem(DBusConnection *connection, DBusMessage *message, void *user_data);
static gboolean __changed_network(DBusConnection *connection, DBusMessage *message, void *user_data);
static gboolean __added_network(DBusConnection *connection, DBusMessage *message, void *user_data);
static gboolean __removed_network(DBusConnection *connection, DBusMessage *message, void *user_data);

// device driver
static struct connman_device_driver modem_driver = {
	.name		= "device",
	.type		= CONNMAN_DEVICE_TYPE_CELLULAR,
	.probe		= __modem_probe,
	.remove		= __modem_remove,
	.enable		= __modem_enable,
	.disable	= __modem_disable,
};

// network driver
static struct connman_network_driver network_driver = {
	.name		= "network",
	.type		= CONNMAN_NETWORK_TYPE_CELLULAR,
	.probe		= __network_probe,
	.remove		= __network_remove,
	.connect	= __network_connect,
	.disconnect	= __network_disconnect,
};

// local function
static void sonet_connect(DBusConnection *connection, void *user_data)
{
	DBG("connection %p", connection);
	modem_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, __remove_modem);
	network_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, __remove_network);
	__request_get_modems();
	return;
}

static void sonet_disconnect(DBusConnection *connection, void *user_data)
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
	struct sonet_modem *modem = data;

	__remove_connman_device(modem);

	g_free(modem->path);
	g_free(modem->operator);
	g_free(modem);
}

static void __remove_network(gpointer data)
{
	struct sonet_network *info = data;
	struct connman_device *device;

	device = connman_network_get_device(info->network);
	if (device != NULL)
		connman_device_remove_network(device, info->network);

	connman_network_unref(info->network);

	g_free(info->path);
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

	return __check_device_online(path, TRUE);
}

static int __modem_disable(struct connman_device *device)
{
	const char *path = connman_device_get_string(device, "Path");
	DBG("device %p, path, %s", device, path);

	return __check_device_online(path, FALSE);
}

static int __network_probe(struct connman_network *network)
{
	DBG("network_prove network(%p)", network);
	return 0;
}

static int __network_connect(struct connman_network *network)
{
	struct connman_device *device;
	struct sonet_modem *modem;

	DBG("network %p", network);

	device = connman_network_get_device(network);
	if (device == NULL)
		return -ENODEV;

	modem = connman_device_get_data(device);
	if (modem == NULL)
		return -ENODEV;

	if (modem->powered == FALSE)
		return -ENOLINK;

	if (modem->online == FALSE)
		return -ENOLINK;

	if (modem->roaming_allowed == FALSE && modem->roaming == TRUE)
		return -ENOLINK;

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

static int __dbus_request(const char *path, const char *interface, const char *method,
			DBusPendingCallNotifyFunction notify, void *user_data,
			DBusFreeFunction free_function, int type, ...)
{
	DBG("sonet request");

	DBusMessage *message;
	DBusPendingCall *call;
	dbus_bool_t ok;
	va_list va;

	DBG("path %s %s.%s", path, interface, method);

	if (path == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call(SONET_SERVICE, path, interface, method);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	va_start(va, type);
	ok = dbus_message_append_args_valist(message, type, va);
	va_end(va);

	if (!ok)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message, &call, TIMEOUT) == FALSE) {
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
	//call connect master
	return __dbus_request("/", SONET_MASTER_INTERFACE, GET_MODEMS,
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
		connman_error("GetModems() %s %s",error.name, error.message);
		dbus_error_free(&error);
		goto done;
	}

	DBG("message signature (%s)", dbus_message_get_signature(reply));

	if (dbus_message_iter_init(reply, &args) == FALSE)
		goto done;

	dbus_message_iter_recurse(&args, &dict);

	//DBG("message type (%d) dic(%d)", dbus_message_iter_get_arg_type(&dict), DBUS_TYPE_DICT_ENTRY);

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

static int __request_get_networks(const char* path)
{
	DBG("request get networks");
	return __dbus_request(path,SONET_MODEM_INTERFACE,GET_NETWORKS,
		__response_get_networks, g_strdup(path), g_free, DBUS_TYPE_INVALID);
}

static void __response_get_networks(DBusPendingCall *call, void *user_data)
{
	DBusError error;
	DBusMessage *reply;
	DBusMessageIter args, dict;

	const char *path = user_data;
	struct sonet_modem *modem;

	DBG("");

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL)
		return;
	if (modem->device == NULL)
		return;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("GetModem() %s %s",error.name, error.message);
		dbus_error_free(&error);
		goto done;
	}

	DBG("message signature (%s)", dbus_message_get_signature(reply));

	if (dbus_message_iter_init(reply, &args) == FALSE)
		goto done;

	dbus_message_iter_recurse(&args, &dict);

	while (dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry, property;
		const char *network_path;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &network_path);
		DBG("network path (%s)", network_path);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &property);

		__add_network(modem->device, network_path, &property);

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

	return __dbus_request(path,SONET_NETWORK_INTERFACE,ACTIVATE_NETWORK,
		__response_network_activate, g_strdup(path), NULL, DBUS_TYPE_INVALID);
}

static void __response_network_activate(DBusPendingCall *call, void *user_data)
{
	DBG("network activation response");

	DBusError error;
	DBusMessage *reply;

	struct sonet_network *info;
	const char* path = user_data;

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
		connman_error("connection activate() %s %s",error.name, error.message);

		if (connman_network_get_index(info->network) < 0)
			connman_network_set_error(info->network, CONNMAN_NETWORK_ERROR_ASSOCIATE_FAIL);

		dbus_error_free(&error);
		goto done;
	}

	if (connman_network_get_index(info->network) >= 0)
		__set_network_connected(info, TRUE);

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

	return __dbus_request(path,SONET_NETWORK_INTERFACE,DEACTIVATE_NETWORK,
		NULL, NULL, NULL, DBUS_TYPE_INVALID);
}

static void __add_modem(const char *path, DBusMessageIter *prop)
{
	struct sonet_modem *modem;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem != NULL)
		return;

	modem = (struct sonet_modem *)malloc( sizeof(struct sonet_modem));
	memset(modem, 0, sizeof(struct sonet_modem));

	modem->path = g_strdup(path);
	modem->device = NULL;

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
		} else if (g_str_equal(key, "roaming") == TRUE) {
			modem->roaming = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "roaming_allowed") == TRUE) {
			modem->roaming_allowed = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "online") == TRUE) {
			modem->online = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "sim_init") == TRUE) {
			modem->sim_init = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "ps_attached") == TRUE) {
			modem->ps_attached = STRING2BOOL(tmp);
		}

		dbus_message_iter_next(prop);
	}

	if (modem->powered != TRUE) {
		DBG("modem is not powered");
		return;
	}

	__set_device_online(modem, modem->online);

	if (modem->online != TRUE) {
		DBG("modem is now off-line. do nothing");
		return;
	}

	__add_connman_device(path, modem->operator);

	return;
}

static void __add_connman_device(const char* modem_path, const char* operator)
{
	struct sonet_modem *modem;
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
		if (!g_strcmp0(operator, connman_device_get_ident(modem->device)))
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
		connman_device_unref(device);
		return;
	}

	modem->device = device;

	if (modem->online == TRUE)
		__request_get_networks(modem_path);

	return;
}

static void __remove_connman_device(struct sonet_modem *modem)
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
		struct sonet_network *info = value;

		if (connman_network_get_device(info->network) != device)
			continue;

		info_list = g_slist_append(info_list, info);
	}

	for (list = info_list; list != NULL; list = list->next) {
		struct sonet_network *info = list->data;
		connman_device_remove_network(device, info->network);
	}

	g_slist_free(info_list);
}

static void __set_device_online(struct sonet_modem *modem, gboolean online)
{
	DBG("set modem(%s) online(%d)", modem->path, online);
	modem->online = online;

	if (modem->device) {
		connman_device_set_powered(modem->device, online);
	}

	return;
}

static int __check_device_online(const char *path, gboolean online)
{
	struct sonet_modem *modem = g_hash_table_lookup(modem_hash, path);

	if (modem == NULL)
		return -ENODEV;

	DBG("check modem (%s) online (%d)", modem->path, modem->online);

	if (modem->online == online)
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

static int __add_network(struct connman_device *device, const char *path, DBusMessageIter *prop)
{
	char *ident;
	gboolean active = FALSE;

	struct sonet_modem *modem = connman_device_get_data(device);
	struct connman_network *network;
	struct sonet_network *info;

	DBG("modem %p device %p path %s", modem, device, path);

	ident = __get_ident(path);

	network = connman_device_get_network(device, ident);
	if (network != NULL)
		return -EALREADY;

	info = g_hash_table_lookup(network_hash, path);
	if (info != NULL) {
		DBG("path %p already exists with device %p", path, connman_network_get_device(info->network));

		if (connman_network_get_device(info->network))
			return -EALREADY;

		g_hash_table_remove(network_hash, path);
	}

	network = connman_network_create(ident, CONNMAN_NETWORK_TYPE_CELLULAR);
	if (network == NULL)
		return -ENOMEM;

	info = (struct sonet_network *)malloc( sizeof(struct sonet_network));
	memset(info, 0, sizeof(struct sonet_network));

	if (info == NULL) {
		connman_network_unref(network);
		return -ENOMEM;
	}

	info->path = g_strdup(path);

	connman_ipaddress_clear(&info->ipv4_address);
	connman_ipaddress_clear(&info->ipv6_address);
	info->network = network;

	connman_network_set_string(network, "Path", path);
	connman_network_set_name(network, path);
	
	__create_service(network);

	g_hash_table_insert(network_hash, g_strdup(path), info);

	connman_network_set_available(network, TRUE);
	connman_network_set_index(network, -1);
	connman_network_set_roaming(network, modem->roaming);

	if (connman_device_add_network(device, network) != 0) {
		g_hash_table_remove(network_hash, path);
		return -EIO;
	}

	active = __set_network_ipconfig(info, prop);

	if (active && connman_network_get_connecting(network) == TRUE)
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

static gboolean __set_network_ipconfig(struct sonet_network *network, DBusMessageIter *dict)
{
	DBG("set network info");

	gboolean active = FALSE;
	char *dev_name=NULL, *proxy_addr=NULL;
	char *ipv4_addr=NULL, *ipv4_gw=NULL, *ipv4_netmask=NULL, *ipv4_dns1=NULL, *ipv4_dns2=NULL;
	char *ipv6_addr=NULL, *ipv6_gw=NULL, *ipv6_netmask=NULL, *ipv6_dns1=NULL, *ipv6_dns2=NULL;

	while (dbus_message_iter_get_arg_type(dict) != DBUS_TYPE_INVALID) {
		DBusMessageIter entry;
		const char* key, *tmp;

		dbus_message_iter_recurse(dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		DBG("key (%s)", key);

		if (g_str_equal(key, "dev_name") == TRUE) {
			dbus_message_iter_get_basic(&entry, &dev_name);
			DBG("dev_name (%s)", dev_name);
		} else if(g_str_equal(key, "proxy") == TRUE) {
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
			active = STRING2BOOL(tmp);
		}

		dbus_message_iter_next(dict);
	}

	// interface index set
	int index = connman_inet_ifindex(dev_name);
	DBG("interface %s, index %d", dev_name, index);
	connman_network_set_index(network->network, index);

	// proxy set
	DBG("proxy (%s) is set", proxy_addr);
	connman_network_set_proxy(network->network, proxy_addr);

	// ipv4 set
	if (g_str_equal(ipv4_addr, "0.0.0.0")) {
		network->ipv4_method = CONNMAN_IPCONFIG_METHOD_OFF;
	} else {
		network->ipv4_method = CONNMAN_IPCONFIG_METHOD_FIXED;
		connman_ipaddress_set_ipv4(&network->ipv4_address, ipv4_addr, ipv4_netmask, ipv4_gw);
		gchar *nameservers = g_strdup_printf("%s %s", ipv4_dns1, ipv4_dns2);
		connman_network_set_nameservers(network->network, nameservers);
	}

	// ipv6 set
	if (g_str_equal(ipv6_addr, "::")) {
		network->ipv6_method = CONNMAN_IPCONFIG_METHOD_OFF;
	} else {
		network->ipv6_method = CONNMAN_IPCONFIG_METHOD_FIXED;
		unsigned char prefix_length = 64;
		connman_ipaddress_set_ipv6(&network->ipv6_address, ipv6_addr, prefix_length, ipv6_gw);
		gchar *nameservers = g_strdup_printf("%s %s", ipv6_dns1, ipv6_dns2);
		connman_network_set_nameservers(network->network, nameservers);
	}

	return active;
}

static void __set_network_connected(struct sonet_network *network, gboolean connected)
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
		connman_network_set_ipv4_method(network->network,network->ipv4_method);
		connman_network_set_ipaddress(network->network, &network->ipv4_address);
		setip = TRUE;
		break;

	case CONNMAN_IPCONFIG_METHOD_DHCP:
		connman_network_set_ipv4_method(network->network, network->ipv4_method);
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
		break;;

	case CONNMAN_IPCONFIG_METHOD_FIXED:
		connman_network_set_ipv6_method(network->network, network->ipv6_method);
		connman_network_set_ipaddress(network->network, &network->ipv6_address);
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

static gboolean __changed_modem(DBusConnection *connection, DBusMessage *message, void *user_data)
{
	DBG("modem changed signal");

	DBusMessageIter args, dict;
	const char *path = dbus_message_get_path(message);
	struct sonet_modem *modem;
	gboolean pre_online = TRUE, roaming_option = TRUE;

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
		const char* key, *tmp;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_get_basic(&entry, &tmp);

		DBG("key(%s), value(%s)", key, tmp);

		if (g_str_equal(key, "powered") == TRUE) {
			modem->powered = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "operator") == TRUE) {
			modem->operator = g_strdup(tmp);
		} else if (g_str_equal(key, "roaming") == TRUE) {
			modem->roaming = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "roaming_allowed") == TRUE) {
			modem->roaming_allowed = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "online") == TRUE) {
			pre_online = modem->online;
			modem->online = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "sim_init") == TRUE) {
			modem->sim_init = STRING2BOOL(tmp);
		} else if (g_str_equal(key, "ps_attached") == TRUE) {
			modem->ps_attached = STRING2BOOL(tmp);
		}

		dbus_message_iter_next(&dict);
	}

	if (modem->powered == FALSE) {
		__remove_connman_device(modem);
		return TRUE;
	}

	if (pre_online != modem->online) {
		__set_device_online(modem, modem->online);

		if (modem->online != TRUE) {
			return TRUE;
		}

		if (modem->device == NULL) {
			__add_connman_device(path, modem->operator);
		} else {
			__request_get_networks(path);
		}

		return TRUE;
	}

	roaming_option &= (!modem->roaming && !modem->roaming_allowed) || modem->roaming_allowed;

	if (modem->ps_attached == TRUE) {
		connman_device_set_cellular_service_enabled(modem->device, roaming_option);
		return TRUE;
	}

	if (roaming_option != TRUE)
		connman_device_set_cellular_service_enabled(modem->device, roaming_option);

	return TRUE;
}

static gboolean __added_modem(DBusConnection *connection, DBusMessage *message, void *user_data)
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

		if (g_str_equal(key, "path") == TRUE) {
			modem_path = g_strdup(value);
		}

		dbus_message_iter_next(&tmp);
	}

	if (modem_path != NULL) {
		__add_modem(modem_path, &dict);
	}

	return TRUE;
}

static gboolean __removed_modem(DBusConnection *connection, DBusMessage *message, void *user_data)
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

static gboolean __changed_network(DBusConnection *connection, DBusMessage *message, void *user_data)
{
	DBG("network changed signal");

	gboolean active = FALSE;
	const char *path = dbus_message_get_path(message);
	struct sonet_network *info;
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
	else if (connman_network_get_connecting(info->network) == TRUE)
		__set_network_connected(info, active);

	return TRUE;
}

static gboolean __added_network(DBusConnection *connection, DBusMessage *message, void *user_data)
{
	DBG("network added signal");

	DBusMessageIter args, dict, tmp;
	const char *path = dbus_message_get_path(message);
	const char *network_path = NULL;
	struct sonet_modem *modem;

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
			network_path = g_strdup(value);
		}

		dbus_message_iter_next(&tmp);
	}

	if (network_path != NULL) {
		__add_network(modem->device, network_path, &dict);
	}

	return TRUE;
}

static gboolean __removed_network(DBusConnection *connection, DBusMessage *message, void *user_data)
{
	DBG("network removed signal");

	DBusMessageIter iter;
	const char *path = dbus_message_get_path(message);
	const char *network_path = NULL;
	struct sonet_modem *modem;

	modem = g_hash_table_lookup(modem_hash, path);
	if (modem == NULL || modem->device == NULL)
		return TRUE;

	if (dbus_message_iter_init(message, &iter) == FALSE) {
		DBG("error to read message");
		return TRUE;
	}

	dbus_message_iter_get_basic(&iter, &network_path);
	g_hash_table_remove(network_hash, network_path);

	return TRUE;
}

/*
static void __response_network_deactivate(DBusPendingCall *call, void *user_data)
{
	struct sonet_network *network;
	DBusMessage *reply;
	DBusError error;
	DBusMessageIter args, dict;

	DBG("");
	network = (struct sonet_network*) user_data;

	reply = dbus_pending_call_steal_reply(call);

	dbus_error_init(&error);

	if (dbus_set_error_from_message(&error, reply)) {
		connman_error("connection deactivate() %s %s",error.name, error.message);
		dbus_error_free(&error);
		goto done;
	}

	DBG("message signature (%s)", dbus_message_get_signature(reply));

	if (dbus_message_iter_init(reply, &args) == FALSE)
		goto done;

	//extract network path
	const char* network_path;
	dbus_message_iter_get_basic(&args, &network_path);

	DBG("network_path is (%s)", network_path);

	//compare the path
	__clean_network_ip_info(network);
	__set_connman_connected(network, FALSE);

done:
	dbus_message_unref(reply);
	dbus_pending_call_unref(call);
	return;
}
*/

// sonet initialization
static guint watch;
static guint modem_watch;
static guint modem_added_watch;
static guint modem_removed_watch;
static guint network_watch;
static guint network_added_watch;
static guint network_removed_watch;

static int sonet_init(void)
{
	DBG("sonet plugin");
	int err;

	connection = connman_dbus_get_connection();
	if (connection == NULL)
		return -EIO;

	// sonet watch
	watch = g_dbus_add_service_watch(connection, SONET_SERVICE,	sonet_connect, sonet_disconnect, NULL, NULL);

	modem_watch = g_dbus_add_signal_watch(connection, NULL, NULL, SONET_MODEM_INTERFACE,
						PROPERTY_CHANGED, __changed_modem, NULL, NULL);

	modem_added_watch = g_dbus_add_signal_watch(connection, NULL, NULL, SONET_MASTER_INTERFACE,
						MODEM_ADDED, __added_modem, NULL, NULL);

	modem_removed_watch = g_dbus_add_signal_watch(connection, NULL, NULL, SONET_MASTER_INTERFACE,
						MODEM_REMOVED, __removed_modem, NULL, NULL);

	network_watch = g_dbus_add_signal_watch(connection, NULL, NULL, SONET_NETWORK_INTERFACE,
						PROPERTY_CHANGED, __changed_network, NULL, NULL);

	network_added_watch = g_dbus_add_signal_watch(connection, NULL, NULL, SONET_MODEM_INTERFACE,
						NETWORK_ADDED, __added_network, NULL, NULL);

	network_removed_watch = g_dbus_add_signal_watch(connection, NULL, NULL, SONET_MODEM_INTERFACE,
						NETWORK_REMOVED, __removed_network, NULL, NULL);

	if (watch == 0 || modem_watch == 0 || modem_added_watch == 0 || modem_removed_watch == 0 ||
			network_watch == 0 || network_added_watch == 0 || network_removed_watch == 0) {
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
	g_dbus_remove_watch(connection, modem_watch);
	g_dbus_remove_watch(connection, modem_added_watch);
	g_dbus_remove_watch(connection, modem_removed_watch);
	g_dbus_remove_watch(connection, network_watch);
	g_dbus_remove_watch(connection, network_added_watch);
	g_dbus_remove_watch(connection, network_removed_watch);

	dbus_connection_unref(connection);
	return err;
}

static void sonet_exit(void)
{
	g_dbus_remove_watch(connection, watch);
	g_dbus_remove_watch(connection, modem_watch);
	g_dbus_remove_watch(connection, modem_added_watch);
	g_dbus_remove_watch(connection, modem_removed_watch);
	g_dbus_remove_watch(connection, network_watch);
	g_dbus_remove_watch(connection, network_added_watch);
	g_dbus_remove_watch(connection, network_removed_watch);

	sonet_disconnect(connection, NULL);

	connman_device_driver_unregister(&modem_driver);
	connman_network_driver_unregister(&network_driver);

	dbus_connection_unref(connection);
}

CONNMAN_PLUGIN_DEFINE(sonet, "Tizen OpenSrc Network Framework plugin", VERSION,
		CONNMAN_PLUGIN_PRIORITY_DEFAULT, sonet_init, sonet_exit)
