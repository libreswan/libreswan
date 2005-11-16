/* FreeS/WAN Pluto launcher (pluto.c)
 * Copyright (C) 2001-2002 Mathieu Lafon - Arkoon Network Security
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 *
 * RCSID $Id: invokepluto.c,v 1.5.16.1 2005/08/18 14:15:57 ken Exp $
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define DEBUG 1

#include "confread.h"
#include "pluto.h"
#include "files.h"
#include "starterwhack.h"
#include "starterlog.h"

#ifndef _OPENSWAN_H
#include <openswan.h>
#include "pluto/constants.h"
#endif

static int _pluto_pid = 0;
static int _stop_requested;

pid_t starter_pluto_pid (void)
{
	return _pluto_pid;
}

void starter_pluto_sigchild (pid_t pid)
{
	if (pid == _pluto_pid) {
		_pluto_pid = 0;
		if (!_stop_requested) {
			starter_log(LOG_LEVEL_ERR,
				"pluto has died -- restart scheduled (%dsec)",
				PLUTO_RESTART_DELAY);
			alarm(PLUTO_RESTART_DELAY);   // restart in 5 sec
		}
		unlink(PID_FILE);
	}
}

int starter_stop_pluto (void)
{
	pid_t pid;
	int i;

	pid = _pluto_pid;
	if (pid) {
		_stop_requested = 1;
		if (starter_whack_shutdown()==0) {
			for (i=0; i<20; i++) {
				usleep(20000);
				if (_pluto_pid == 0) return 0;
			}
		}
		/**
		 * Be more and more aggressive
		 */
		for (i=0; (i<20) && ((pid=_pluto_pid)!=0); i++) {
			if (i<10) kill(pid, SIGTERM);
			else kill(pid, SIGKILL);
			usleep(20000);
		}
		if (_pluto_pid == 0) return 0;
		starter_log(LOG_LEVEL_ERR, "stater_stop_pluto(): can't stop pluto !!!");
		return -1;
	}
	else {
		starter_log(LOG_LEVEL_ERR,
			"stater_stop_pluto(): pluto is not started...");
	}
	return -1;
}

#define ADD_DEBUG(flag, v) do { \
	if(cfg->setup.options[KBF_PLUTODEBUG] & flag) { \
		arg[argc++] = "--debug-" v; \
	}} while(0)

int starter_start_pluto (struct starter_config *cfg, int debug)
{
	int i;
	struct stat stb;
	pid_t pid;
	char *arg[] = { PLUTO_CMD, "--nofork", NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL };
	int argc = 2;

	if (debug) {
		arg[argc++] = "--stderrlog";
	}
	if (cfg->setup.options[KBF_UNIQUEIDS]) {
		arg[argc++] = "--uniqueids";
	}
	if(cfg->setup.options[KBF_PLUTODEBUG] & DBG_ALL)
	{
	    arg[argc++] = "--debug-all";
	} else {
	    ADD_DEBUG(DBG_RAW,   "raw");
	    ADD_DEBUG(DBG_CRYPT, "crypt");
	    ADD_DEBUG(DBG_PARSING,"parsing");
	    ADD_DEBUG(DBG_EMITTING,"emitting");
	    ADD_DEBUG(DBG_CONTROL, "control");
	    ADD_DEBUG(DBG_CONTROLMORE, "controlmore");
	    ADD_DEBUG(DBG_KLIPS, "klips");
	    ADD_DEBUG(DBG_DNS,   "dns");
	    ADD_DEBUG(DBG_OPPO,  "oppo");
	    ADD_DEBUG(DBG_PRIVATE, "private");
	    ADD_DEBUG(IMPAIR_DELAY_ADNS_KEY_ANSWER, "impair-delay-adns-key-answer");
	    ADD_DEBUG(IMPAIR_DELAY_ADNS_TXT_ANSWER,"impair-delay-adns-txt-answer");
	    ADD_DEBUG(IMPAIR_BUST_MI2, "impair-bust-mi2");
	    ADD_DEBUG(IMPAIR_BUST_MR2, "impair-bust-mr2");
	}

	if (cfg->setup.strictcrlpolicy) {
		arg[argc++] = "--strictcrlpolicy";
	}
	if (cfg->setup.nocrsend) {
		arg[argc++] = "--nocrsend";
	}
#ifdef NAT_TRAVERSAL
	{
		static char ka[15];
		if (cfg->setup.nat_traversal) {
			arg[argc++] = "--nat_traversal";
		}
		if (cfg->setup.keep_alive) {
			arg[argc++] = "--keep_alive";
			sprintf(ka, "%u", cfg->setup.keep_alive);
			arg[argc++] = ka;
		}
	}
#endif
#ifdef VIRTUAL_IP
	if (cfg->setup.virtual_private) {
		arg[argc++] = "--virtual_private";
		arg[argc++] = cfg->setup.virtual_private;
	}
#endif

	if (_pluto_pid) {
		starter_log(LOG_LEVEL_ERR,
			"starter_start_pluto(): pluto already started...");
		return -1;
	}
	else {
		sigset_t sig;
		unlink(CTL_FILE);
		_stop_requested = 0;

		if (cfg->setup.strings[KSF_PREPLUTO]) system(cfg->setup.strings[KSF_PREPLUTO]);

		pid = fork();
		switch (pid) {
			case -1:
				starter_log(LOG_LEVEL_ERR, "can't fork(): %s", strerror(errno));
				return -1;
				break;
			case 0:
				/**
				 * Child
				 */
				setsid();
				sigemptyset(&sig);
				sigprocmask(SIG_SETMASK,&sig,NULL);
				execv(arg[0], arg);
				starter_log(LOG_LEVEL_ERR, "can't execv(%s,...): %s", arg[0],
					strerror(errno));
				exit(1);
				break;
			default:
				/**
				 * Father
				 */
				_pluto_pid = pid;
				for (i=0; (i<50) && (_pluto_pid); i++) {
					/**
					 * Wait for pluto
					 */
					usleep(20000);
					if (stat(CTL_FILE, &stb)==0) {
						starter_log(LOG_LEVEL_INFO, "pluto (%d) started",
							_pluto_pid);
						if (cfg->setup.strings[KSF_POSTPLUTO])
						{
						    system(cfg->setup.strings[KSF_POSTPLUTO]);
						}
						return 0;
					}
				}
				if (_pluto_pid) {
					/**
					 * If pluto is started but with no ctl file, stop it
					 */
					starter_log(LOG_LEVEL_ERR,
						"pluto too long to start... - kill kill");
					for (i=0; (i<20) && ((pid=_pluto_pid)!=0); i++) {
						if (i<10) kill(pid, SIGTERM);
						else kill(pid, SIGKILL);
						usleep(20000);
					}
				}
				else {
					starter_log(LOG_LEVEL_ERR, "pluto refused to be started");
				}
				return -1;
				break;
		}
	}
	return -1;
}

/*
 * Local Variables:
 * c-basic-offset:4
 * c-style: pluto
 * End:
 */
