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

#define _GNU_SOURCE
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <execinfo.h>
#include <dlfcn.h>

#include "connman.h"

#if defined TIZEN_EXT
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#define LOG_FILE_PATH "/var/log/connman.log"
#define MAX_LOG_SIZE	2 * 1024 * 1024
#define MAX_LOG_COUNT	9

#define openlog __connman_log_open
#define closelog __connman_log_close
#define vsyslog __connman_log
#define syslog __connman_log_s

static FILE *log_file = NULL;

void __connman_log_open(const char *ident, int option, int facility)
{
	if (log_file == NULL)
		log_file = (FILE *)fopen(LOG_FILE_PATH, "a+");
}

void __connman_log_close(void)
{
	fclose(log_file);
	log_file = NULL;
}

static void __connman_log_update_file_revision(int rev)
{
	int next_log_rev = 0;
	char *log_file = NULL;
	char *next_log_file = NULL;

	next_log_rev = rev + 1;

	log_file = g_strdup_printf("%s.%d", LOG_FILE_PATH, rev);
	next_log_file = g_strdup_printf("%s.%d", LOG_FILE_PATH, next_log_rev);

	if (next_log_rev >= MAX_LOG_COUNT)
		remove(next_log_file);

	if (access(next_log_file, F_OK) == 0)
		__connman_log_update_file_revision(next_log_rev);

	if (rename(log_file, next_log_file) != 0)
		remove(log_file);

	g_free(log_file);
	g_free(next_log_file);
}

static void __connman_log_make_backup(void)
{
	const int rev = 0;
	char *backup = NULL;

	backup = g_strdup_printf("%s.%d", LOG_FILE_PATH, rev);

	if (access(backup, F_OK) == 0)
		__connman_log_update_file_revision(rev);

	if (rename(LOG_FILE_PATH, backup) != 0)
		remove(LOG_FILE_PATH);

	g_free(backup);
}

static void __connman_log_get_local_time(char *strtime, const int size)
{
	time_t buf;
	struct tm *local_ptm;

	time(&buf);
	buf = time(NULL);
	local_ptm = localtime(&buf);

	strftime(strtime, size, "%D %H:%M:%S", local_ptm);
}

void __connman_log(const int log_priority, const char *format, va_list ap)
{
	int log_size = 0;
	struct stat buf;
	char str[256];
	char strtime[40];

	if (log_file == NULL)
		log_file = (FILE *)fopen(LOG_FILE_PATH, "a+");

	if (log_file == NULL)
		return;

	fstat(fileno(log_file), &buf);
	log_size = buf.st_size;

	if (log_size >= MAX_LOG_SIZE) {
		fclose(log_file);
		log_file = NULL;

		__connman_log_make_backup();

		log_file = (FILE *)fopen(LOG_FILE_PATH, "a+");

		if (log_file == NULL)
			return;
	}

	__connman_log_get_local_time(strtime, sizeof(strtime));

	if (vsnprintf(str, sizeof(str), format, ap) > 0)
		fprintf(log_file, "%s %s\n", strtime, str);
}

void __connman_log_s(int log_priority, const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_DEBUG, format, ap);

	va_end(ap);
}
#endif

/**
 * connman_info:
 * @format: format string
 * @Varargs: list of arguments
 *
 * Output general information
 */
void connman_info(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_INFO, format, ap);

	va_end(ap);
}

/**
 * connman_warn:
 * @format: format string
 * @Varargs: list of arguments
 *
 * Output warning messages
 */
void connman_warn(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_WARNING, format, ap);

	va_end(ap);
}

/**
 * connman_error:
 * @format: format string
 * @varargs: list of arguments
 *
 * Output error messages
 */
void connman_error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_ERR, format, ap);

	va_end(ap);
}

/**
 * connman_debug:
 * @format: format string
 * @varargs: list of arguments
 *
 * Output debug message
 */
void connman_debug(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	vsyslog(LOG_DEBUG, format, ap);

	va_end(ap);
}

#if !defined TIZEN_EXT
static void signal_handler(int signo)
{
	void *frames[64];
	char **symbols;
	size_t n_ptrs;
	unsigned int i;

	n_ptrs = backtrace(frames, G_N_ELEMENTS(frames));
	symbols = backtrace_symbols(frames, n_ptrs);
	if (symbols == NULL) {
		connman_error("No backtrace symbols");
		exit(1);
	}

	connman_error("Aborting (signal %d)", signo);
	connman_error("++++++++ backtrace ++++++++");

	for (i = 1; i < n_ptrs; i++)
		connman_error("[%d]: %s", i - 1, symbols[i]);

	connman_error("+++++++++++++++++++++++++++");

	g_free(symbols);
	exit(1);
}

static void signal_setup(sighandler_t handler)
{
	struct sigaction sa;
	sigset_t mask;

	sigemptyset(&mask);
	sa.sa_handler = handler;
	sa.sa_mask = mask;
	sa.sa_flags = 0;
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
}
#endif

extern struct connman_debug_desc __start___debug[];
extern struct connman_debug_desc __stop___debug[];

void __connman_debug_list_available(DBusMessageIter *iter, void *user_data)
{
	struct connman_debug_desc *desc;

	for (desc = __start___debug; desc < __stop___debug; desc++) {
		if ((desc->flags & CONNMAN_DEBUG_FLAG_ALIAS) &&
						desc->name != NULL)
			dbus_message_iter_append_basic(iter,
					DBUS_TYPE_STRING, &desc->name);
	}
}

static gchar **enabled = NULL;

void __connman_debug_list_enabled(DBusMessageIter *iter, void *user_data)
{
	int i;

	if (enabled == NULL)
		return;

	for (i = 0; enabled[i] != NULL; i++)
		dbus_message_iter_append_basic(iter,
					DBUS_TYPE_STRING, &enabled[i]);
}

static connman_bool_t is_enabled(struct connman_debug_desc *desc)
{
	int i;

	if (enabled == NULL)
		return FALSE;

	for (i = 0; enabled[i] != NULL; i++) {
		if (desc->name != NULL && g_pattern_match_simple(enabled[i],
							desc->name) == TRUE)
			return TRUE;
		if (desc->file != NULL && g_pattern_match_simple(enabled[i],
							desc->file) == TRUE)
			return TRUE;
	}

	return FALSE;
}

void __connman_log_enable(struct connman_debug_desc *start,
					struct connman_debug_desc *stop)
{
	struct connman_debug_desc *desc;
	const char *name = NULL, *file = NULL;

	if (start == NULL || stop == NULL)
		return;

	for (desc = start; desc < stop; desc++) {
		if (desc->flags & CONNMAN_DEBUG_FLAG_ALIAS) {
			file = desc->file;
			name = desc->name;
			continue;
		}

		if (file != NULL || name != NULL) {
			if (g_strcmp0(desc->file, file) == 0) {
				if (desc->name == NULL)
					desc->name = name;
			} else
				file = NULL;
		}

		if (is_enabled(desc) == TRUE)
			desc->flags |= CONNMAN_DEBUG_FLAG_PRINT;
	}
}

int __connman_log_init(const char *debug, connman_bool_t detach)
{
	int option = LOG_NDELAY | LOG_PID;

	if (debug != NULL)
		enabled = g_strsplit_set(debug, ":, ", 0);

	__connman_log_enable(__start___debug, __stop___debug);

	if (detach == FALSE)
		option |= LOG_PERROR;

#if !defined TIZEN_EXT
	signal_setup(signal_handler);
#endif

	openlog("connmand", option, LOG_DAEMON);

	syslog(LOG_INFO, "Connection Manager version %s", VERSION);

	return 0;
}

void __connman_log_cleanup(void)
{
	syslog(LOG_INFO, "Exit");

	closelog();

#if !defined TIZEN_EXT
	signal_setup(SIG_DFL);
#endif

	g_strfreev(enabled);
}
