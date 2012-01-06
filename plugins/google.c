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
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define CONNMAN_API_SUBJECT_TO_CHANGE
#include <connman/plugin.h>
#include <connman/resolver.h>

#define GOOGLE_DNS1	"8.8.8.8"
#define GOOGLE_DNS2	"8.8.4.4"

static int google_init(void)
{
	connman_resolver_append_public_server(GOOGLE_DNS1);
	connman_resolver_append_public_server(GOOGLE_DNS2);

	return 0;
}

static void google_exit(void)
{
	connman_resolver_remove_public_server(GOOGLE_DNS2);
	connman_resolver_remove_public_server(GOOGLE_DNS1);
}

CONNMAN_PLUGIN_DEFINE(google, "Google Public DNS plugin", VERSION,
			CONNMAN_PLUGIN_PRIORITY_LOW, google_init, google_exit)
