 /*
  *
  *  Connection Manager
  *
  *  Copyright (C) 2007-2010  Intel Corporation. All rights reserved.
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
  *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA	02110-1301	USA
  *
  */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <string.h>
#include <gdbus.h>
#include <errno.h>
#include <stdlib.h>

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/notifier.h>
#include <connman/service.h>
#include <connman/network.h>
#include <connman/ipconfig.h>
#include <connman/dbus.h>
#include <connman/log.h>

#define TIMEOUT_DEFAULT		5
#define TIMEOUT_MAX			1280

guint connection_timeout;
guint	timer_src;
static gboolean cellular_enabled = FALSE;

static DBusConnection *connection;
struct connman_service *celluar_default_service;
struct connman_service *connected_default_service;

int __request_service_connect(struct connman_service *service);
void __request_service_disconnect(struct connman_service *service);
void __unset_default_connected_service(struct connman_service *service, enum connman_service_state state);
void __set_default_connected_service(struct connman_service *service, enum connman_service_state state);
static gboolean __connect_timeout_handler(gpointer user_data);
static void __reset_retry_timer(void);

//tmp code - send the default connection info to sonet
static int __dbus_request(const char *path, const char *interface, const char *method,
			DBusPendingCallNotifyFunction notify, void *user_data,
			DBusFreeFunction free_function, int type, ...);
void __send_default_connection_info(struct connman_service *service, enum connman_service_state state);

const char *__always_on_service_type2string(enum connman_service_type type)
{
	switch (type) {
	case CONNMAN_SERVICE_TYPE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_TYPE_SYSTEM:
		return "system";
	case CONNMAN_SERVICE_TYPE_ETHERNET:
		return "ethernet";
	case CONNMAN_SERVICE_TYPE_WIFI:
		return "wifi";
	case CONNMAN_SERVICE_TYPE_WIMAX:
		return "wimax";
	case CONNMAN_SERVICE_TYPE_BLUETOOTH:
		return "bluetooth";
	case CONNMAN_SERVICE_TYPE_CELLULAR:
		return "cellular";
	case CONNMAN_SERVICE_TYPE_GPS:
		return "gps";
	case CONNMAN_SERVICE_TYPE_VPN:
		return "vpn";
	case CONNMAN_SERVICE_TYPE_GADGET:
		return "gadget";
	}

	return NULL;
}

const char *__always_on_state2string(enum connman_service_state state)
{
	switch (state) {
	case CONNMAN_SERVICE_STATE_UNKNOWN:
		break;
	case CONNMAN_SERVICE_STATE_IDLE:
		return "idle";
	case CONNMAN_SERVICE_STATE_ASSOCIATION:
		return "association";
	case CONNMAN_SERVICE_STATE_CONFIGURATION:
		return "configuration";
	case CONNMAN_SERVICE_STATE_READY:
		return "ready";
	case CONNMAN_SERVICE_STATE_ONLINE:
		return "online";
	case CONNMAN_SERVICE_STATE_DISCONNECT:
		return "disconnect";
	case CONNMAN_SERVICE_STATE_FAILURE:
		return "failure";
	}

	return NULL;
}


static void __always_on_service_added(struct connman_service *service, const char *name)
{
	DBG("service added notifier");
	struct connman_network *network;
	const char *path = NULL;
	int service_type = 0, svc_category_id = 0;

	service_type = connman_service_get_type(service);
	network = connman_service_get_network(service);
	path = connman_network_get_string(network,"Name");

	if(service_type != CONNMAN_SERVICE_TYPE_CELLULAR){
		DBG("service type is not cellular device");
		return;
	}

	gchar **strv;
	int index = 0;

	strv = g_strsplit_set(path, "_", -1);
	index = g_strv_length(strv);
	svc_category_id = atoi(strv[index-1]);
	g_strfreev(strv);

	DBG("svc category id (%d)",svc_category_id);

	//internet service
	if(svc_category_id == 1){
		celluar_default_service = service;

		__reset_retry_timer();

		DBG("cellular internet service path (%s), service(%p) added", path, service);

		if(connected_default_service == NULL){
			DBG("request to connect default cellular service");
			__request_service_connect(service);
		}
	}

	return;
}

static void __always_on_service_removed(struct connman_service *service)
{
	DBG("service removed notifier");
	int service_type = 0;

	service_type = connman_service_get_type(service);
	if(service_type != CONNMAN_SERVICE_TYPE_CELLULAR){
		DBG("service type is not cellular device");
		return;
	}

	if(celluar_default_service == service){
		DBG("cellular internet service removed");
		celluar_default_service = NULL;

		__reset_retry_timer();

		if(connected_default_service == service){
			DBG("default connected service removed");
			connected_default_service = NULL;
			__send_default_connection_info(service, CONNMAN_SERVICE_STATE_IDLE);
		}
	}

	return;
}

static void __always_on_service_enabled(enum connman_service_type type, connman_bool_t enabled)
{
	DBG("service enabled notifier");
	return;
}

void __always_on_cellular_service_enabled(connman_bool_t enabled)
{
	cellular_enabled = enabled;

	__reset_retry_timer();
	DBG("device cellular service  enabled notifier");

	if(celluar_default_service == NULL){
		DBG("no cellular default service");
		return;
	}

	if(enabled && connected_default_service == NULL){
		DBG("connect default cellular service");
		__request_service_connect(celluar_default_service);

	}
	else if(enabled == FALSE && connected_default_service == celluar_default_service){
		DBG("disconnect default cellular service");
		__request_service_disconnect(celluar_default_service);
	}

	return;
}

static void __always_on_service_state_changed(struct connman_service *service, enum connman_service_state state)
{
	if(state > CONNMAN_SERVICE_STATE_IDLE  && state < CONNMAN_SERVICE_STATE_READY){
		return;
	}

	DBG("service state changed service type[%d] state[%d]",connman_service_get_type(service), state);

	if(state == CONNMAN_SERVICE_STATE_IDLE){
		__unset_default_connected_service(service, state);
	}
	else if(state == CONNMAN_SERVICE_STATE_READY){
		__set_default_connected_service(service, state);
	}
	else if(state == CONNMAN_SERVICE_STATE_FAILURE && celluar_default_service == service){
		DBG("fail to connect default cellular service(%p)", service);

		if(connected_default_service == NULL && cellular_enabled ){
			timer_src = g_timeout_add_seconds(connection_timeout, __connect_timeout_handler, service);
			DBG("cellular service timer started timer src(%d), timeout(%d)", timer_src, connection_timeout);

			connection_timeout = connection_timeout*2;
			if(connection_timeout > TIMEOUT_MAX)
				connection_timeout = TIMEOUT_MAX;
		}

	}

	return;
}

static void  __always_on_service_proxy_changed(struct connman_service *service)
{
	DBG("service proxy changed notifier");
	int service_state = 0;

	if(connected_default_service == NULL ||service != connected_default_service){
		return;
	}

	service_state = CONNMAN_SERVICE_STATE_READY;
	__send_default_connection_info(service, service_state);

	return;
}

int __request_service_connect(struct connman_service *service)
{
	int err = 0;
	int service_type = 0;

	if (service == NULL) {
		DBG("requested service is null");
		return;
	}

	service_type = connman_service_get_type(service);
	if (service_type == CONNMAN_SERVICE_TYPE_CELLULAR) {
		connman_service_set_alwayson(service, TRUE);
	}

	err = connman_service_connect(service);
	DBG("return value (%d)", err);

	return err;
}

void __request_service_disconnect(struct connman_service *service)
{
	int service_type = 0;

	if (service == NULL) {
		DBG("requested service is null");
		return;
	}

	service_type = connman_service_get_type(service);
	if (service_type == CONNMAN_SERVICE_TYPE_CELLULAR) {
		connman_service_set_alwayson(service, FALSE);
	}

	connman_service_disconnect(service);
	return;
}

void __unset_default_connected_service(struct connman_service *service, enum connman_service_state state)
{
	int service_type = 0;
	int err = 0;
	service_type = connman_service_get_type(service);

	if(service_type == CONNMAN_SERVICE_TYPE_CELLULAR && celluar_default_service != service){
		DBG("not a default cellular service");
		return;
	}

	if(connected_default_service == NULL || connected_default_service == service){
		DBG("request default cellular service connect");
		connected_default_service = NULL;
		__send_default_connection_info(service, state);
		err = __request_service_connect(celluar_default_service);

		if (err == -EISCONN) {
			__send_default_connection_info(celluar_default_service, CONNMAN_SERVICE_STATE_READY);
		}
		return;
	}

	DBG("current default connected service (%p)", connected_default_service);
	return;
}

void __set_default_connected_service(struct connman_service *service, enum connman_service_state state)
{
	int service_type = 0;
	service_type = connman_service_get_type(service);

	if(service_type == CONNMAN_SERVICE_TYPE_CELLULAR && celluar_default_service != service){
		DBG("not a default cellular service");
		return;
	}

	__reset_retry_timer();

	//set default connection service
	if(connected_default_service == NULL || connected_default_service == service ){
		DBG("set connected default service");
		connected_default_service = service;
		__send_default_connection_info(service, state);
		return;
	}

	//connected_default_service != service
	if(connected_default_service == celluar_default_service){
		DBG("set connected default service");
		connected_default_service = service;
		__send_default_connection_info(service, state);
		//check cellualr connection user request
		if(connman_service_is_no_ref_user_initiated_pdp_connection(celluar_default_service)){
			__request_service_disconnect(celluar_default_service);
			return;
		}
	}

	//disconnect default cellular service when other service is connected
	if(service_type == CONNMAN_SERVICE_TYPE_CELLULAR && celluar_default_service == service){
		DBG("disconnect lazy cellular service");
		if(connman_service_is_no_ref_user_initiated_pdp_connection(celluar_default_service)){
			__request_service_disconnect(celluar_default_service);
			return;
		}
	}

	DBG("current default connected service (%p)", connected_default_service);
	return;
}

static int __dbus_request(const char *path, const char *interface, const char *method,
			DBusPendingCallNotifyFunction notify, void *user_data,
			DBusFreeFunction free_function, int type, ...){

	DBG("dbus request");

	DBusMessage *message;
	DBusPendingCall *call;
	dbus_bool_t ok;
	va_list va;

	DBG("path %s %s.%s", path, interface, method);

	if (path == NULL)
		return -EINVAL;

	message = dbus_message_new_method_call("net.sonet", path, interface, method);
	if (message == NULL)
		return -ENOMEM;

	dbus_message_set_auto_start(message, FALSE);

	va_start(va, type);
	ok = dbus_message_append_args_valist(message, type, va);
	va_end(va);

	if (!ok)
		return -ENOMEM;

	if (dbus_connection_send_with_reply(connection, message, &call, 40000) == FALSE) {
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

void __send_default_connection_info(struct connman_service *service, enum connman_service_state state)
{
	struct connman_ipconfig *ip_config = NULL;
	gchar *connection_type = NULL, *connection_state = NULL, *ip_addr = NULL, *proxy_addr = NULL;
	int service_type = 0;
	gchar **proxy_list = NULL;

	service_type = connman_service_get_type(service);
	const char* tmp = __always_on_service_type2string(service_type);
	connection_type = g_strdup(tmp);

	tmp = __always_on_state2string(state);
	connection_state = g_strdup(tmp);

	ip_config = connman_service_get_ipv4config(service);
	DBG("ip_config %p", ip_config);
	if (ip_config == NULL)
		return;

	tmp = connman_ipconfig_get_local(ip_config);
	ip_addr = g_strdup(tmp);

	proxy_list = connman_service_get_proxy_servers(service);
	if(proxy_list != NULL){
		proxy_addr = g_strdup(proxy_list[0]);
	}

	if(ip_addr == NULL)
		ip_addr = g_strdup("");

	if(proxy_addr == NULL)
		proxy_addr = g_strdup("");

	__dbus_request("/", "net.sonet.master", "UpdateDefaultConnectionInfo",
		NULL, NULL, NULL,
		DBUS_TYPE_STRING,&connection_type, DBUS_TYPE_STRING,&connection_state,
		DBUS_TYPE_STRING,&ip_addr, DBUS_TYPE_STRING,&proxy_addr,DBUS_TYPE_INVALID);

	g_free(connection_type);
	g_free(connection_state);
	g_free(ip_addr);
	g_free(proxy_addr);
	g_strfreev(proxy_list);

	return;
}

static gboolean __connect_timeout_handler(gpointer user_data)
{
	DBG("connection timeout");

	struct connman_service *service = (struct connman_service *)user_data;

	__request_service_connect(service);
	timer_src = 0;

	return FALSE;
}

static void __reset_retry_timer(void)
{
	connection_timeout = TIMEOUT_DEFAULT;

	if (timer_src != 0) {
		DBG("remove connection retry timer (%d)", timer_src);
		g_source_remove(timer_src);
		timer_src = 0;
	}

	return;
}

static struct connman_notifier notifier = {
	.name		= "alwayson",
	.priority	= CONNMAN_NOTIFIER_PRIORITY_HIGH,
	.default_changed = NULL,
	.service_add = __always_on_service_added,
	.service_remove = __always_on_service_removed,
	.service_enabled = __always_on_service_enabled,
	.offline_mode = NULL,
	.cellular_service_enabled = __always_on_cellular_service_enabled,
	.proxy_changed = __always_on_service_proxy_changed,
	.service_state_changed= __always_on_service_state_changed,
	.ipconfig_changed = NULL,
};

static int alwayson_init(void)
{
	DBG("alwayson init");
	connection = connman_dbus_get_connection();
	connman_notifier_register(&notifier);
	connection_timeout = TIMEOUT_DEFAULT;
	return 0;
}

static void alwayson_exit(void)
{
	return;
}

CONNMAN_PLUGIN_DEFINE(alwayson, "AlwaysOn features plugin", VERSION,
			CONNMAN_PLUGIN_PRIORITY_DEFAULT, alwayson_init, alwayson_exit)
