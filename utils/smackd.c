/*
 * This file is part of libsmack
 *
 * Copyright (C) 2011 Intel Corporation
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 *
 * Authors:
 * Brian McGillion <brian.mcgillion@intel.com>
 */

#include "common.h"
#include <signal.h>
#include <syslog.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/select.h>

#define PID_FILE "/var/run/smackd.pid"
#define BUF_SIZE (4 * (sizeof(struct inotify_event) + NAME_MAX + 1))

#define ACCESS_FD 0
#define CIPSO_FD 1

int notify_handles[2];
static volatile sig_atomic_t terminate = 0;
static volatile sig_atomic_t restart = 0;

enum mask_action {
	CREATE,
	MODIFY,
	DELETE
};

static void clear_all_rules()
{
	if (clear() == -1)
		syslog(LOG_ERR, "Failed to clear all rules");
}

static void load_all_rules()
{
	if (apply_rules(ACCESSES_D_PATH, 0))
		syslog(LOG_DEBUG, "Failed to load all rules");
}

static void signal_handler(int sig)
{
	switch (sig) {
	case SIGTERM:
		terminate = 1;
		break;
	case SIGHUP:
		restart = 1;
		break;
	default:
		syslog(LOG_DEBUG, "Unrequested signal : %d", sig);
		break;
	}
}

static int lockPidFile()
{
	int fd;
	struct flock lock;
	char buf[BUF_SIZE];

	fd = open(PID_FILE, O_RDWR | O_CREAT | O_CLOEXEC,
		  S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd < 0) {
		syslog(LOG_ERR, "Failed to open (%s) : %m", PID_FILE);
		return -1;
	}

	lock.l_len = 0;
	lock.l_start = 0;
	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;

	if (fcntl(fd, F_SETLK, &lock) < 0) {
		if (errno == EACCES || errno == EAGAIN) {
			syslog(LOG_ERR, "Daemon is already running (%s) : %m", PID_FILE);
		}
		else
			syslog(LOG_ERR, "Could not lock PID_FILE (%s) : %m", PID_FILE);

		close(fd);
		return -1;
	}

	if (ftruncate(fd, 0) < 0) {
		syslog(LOG_ERR, "Could not truncate PID_FILE (%s) : %m", PID_FILE);
		close(fd);
		return -1;
	}

	snprintf(buf, BUF_SIZE, "%ld\n", (long)getpid());
	if (write(fd, buf, strlen(buf)) != strlen(buf)) {
		syslog(LOG_ERR, "Could not write to PID_FILE (%s) : %m", PID_FILE);
		close(fd);
		return -1;
	}

	return fd;
}

static int daemonize()
{
	int maxfd, fd;

	switch (fork()) {
	case -1:
		syslog(LOG_ERR, "Failed to fork : %m");
		return -1;
	case 0:
		break;
	default:
		exit(EXIT_SUCCESS);
	}

	if (setsid() < 0)
		return -1;

	//do not regain a terminal
	switch (fork()) {
	case -1:
		syslog(LOG_ERR, "Failed to fork (2) : %m");
		return -1;
	case 0:
		break;
	default:
		exit(EXIT_SUCCESS);
	}

	umask(0);

	if (chdir("/") < 0)
		syslog(LOG_ERR, "Failed to chdir '/' : %m");

	maxfd = sysconf(_SC_OPEN_MAX);
	maxfd = maxfd != -1 ? maxfd : 4096;

	for (fd = 0; fd < maxfd; fd++)
		close(fd);

	if (!freopen("/dev/null", "r", stdin))
		syslog(LOG_DEBUG, "Failed to reopen stdin : %m");
	if(!freopen("/dev/null", "w", stdout))
		syslog(LOG_DEBUG, "Failed to reopen stout : %m");
	if(!freopen("/dev/null", "w", stderr))
		syslog(LOG_DEBUG, "Failed to reopen sterr : %m");

	return lockPidFile();
}

static int configure_inotify()
{
	int inotifyFd, fd;

	inotifyFd = inotify_init();
	if (inotifyFd < 0) {
		syslog(LOG_ERR, "Failed to init inotify : %m");
		return -1;
	}

	fd = inotify_add_watch(inotifyFd, ACCESSES_D_PATH,
			       IN_DELETE | IN_CLOSE_WRITE | IN_MOVE);
	if (fd < 0) {
		syslog(LOG_ERR, "Failed to inotify_add_watch (%s) : %m",
		       ACCESSES_D_PATH);
		return -1;
	}

	notify_handles[ACCESS_FD] = fd;

	fd = inotify_add_watch(inotifyFd, CIPSO_D_PATH,
			       IN_DELETE | IN_CLOSE_WRITE | IN_MOVE);
	if (fd < 0) {
		syslog(LOG_ERR, "Failed to inotify_add_watch (%s) : %m",
		       CIPSO_D_PATH);
		return -1;
	}

	notify_handles[CIPSO_FD] = fd;

	return inotifyFd;
}

static void modify_access_rules(char *file, enum mask_action action)
{
	char path[PATH_MAX];
	int ret;

	sprintf(path,"%s/%s", ACCESSES_D_PATH, file);

	if (action == CREATE)
		ret = apply_rules(path, 0);
	else if (action == MODIFY) {
		ret = apply_rules(path, 1);
		ret = apply_rules(path, 0);
	}

	if (ret)
		syslog(LOG_ERR, "Failed load access rules (%s), action (%d) :%m",
		       path, action);
}

static void modify_cipso_rules(char *file)
{
	char path[PATH_MAX];
	sprintf(path,"%s/%s", CIPSO_D_PATH, file);

	if (apply_cipso(path))
		syslog(LOG_ERR, "Failed to load cipso rules (%s) : %m", path);
}

static int handle_inotify_event(int inotifyFd)
{
	struct inotify_event *event;
	char buf[BUF_SIZE];
	ssize_t num_read;
	char *head;
	enum mask_action action;
	int del = 0;
	int size = sizeof(struct inotify_event);

	num_read = read(inotifyFd, buf, BUF_SIZE);
	if (num_read <= 0) {
		syslog(LOG_ERR, "Error reading inotify event : %m");
		return -1;
	}

	for (head = buf; head < buf + num_read; head += size + event->len) {
		event = (struct inotify_event *) head;

		if (event->mask & IN_MOVED_TO)
			action = CREATE;
		else if (event->mask & IN_CLOSE_WRITE)
			action = MODIFY;
		else if (event->mask & IN_DELETE || event->mask & IN_MOVED_FROM) {
			del = 1;
			continue;
		}

		if (event->wd == notify_handles[ACCESS_FD])
			modify_access_rules(event->name, action);
		else if (event->wd == notify_handles[CIPSO_FD])
			modify_cipso_rules(event->name);
	}

	if (del) {
		//at least one file was removed so we should reparse the rules
		clear_all_rules();
		load_all_rules();
	}

	return 0;
}

static int monitor(int inotifyFd)
{
	fd_set readSet;
	FD_ZERO(&readSet);
	FD_SET(inotifyFd, &readSet);

	return select(inotifyFd + 1, &readSet, NULL, NULL, NULL);
}

void main(int argc, char **argv)
{
	struct sigaction sa;
	int inotify_fd;
	int ret;
	int pid_fd;

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = signal_handler;
	sa.sa_flags = SA_RESTART;

	if (sigaction(SIGHUP, &sa, NULL) < 0) {
		syslog(LOG_ERR, "failed to listen for signal SIGHUP : %m");
		exit(EXIT_FAILURE);
	}

	if (sigaction(SIGTERM, &sa, NULL) < 0) {
		syslog(LOG_ERR, "failed to listen for signal SIGTERM : %m");
		exit(EXIT_FAILURE);
	}

	pid_fd = daemonize();
	if (pid_fd < 0)
		exit(EXIT_FAILURE);

	clear_all_rules();
	load_all_rules();

	inotify_fd = configure_inotify();

	while (inotify_fd >= 0 && !terminate && !restart) {
		ret = monitor(inotify_fd);
		if (ret < 0 && errno == EINTR) {
			continue;
		}
		else if (ret < 0) {
			syslog(LOG_ERR, "Failed to monitor properly : %m");
			break;
		}

		ret = handle_inotify_event(inotify_fd);
		if (ret < 0)
			break;
	}

	close(pid_fd);
	remove(PID_FILE);

	if (restart && execv(argv[0], argv))
		syslog(LOG_ERR, "Failed to restart : %m");

	clear_all_rules();

	syslog(LOG_DEBUG, "Finished %s", argv[0]);
	exit(terminate == 1 ? EXIT_SUCCESS : EXIT_FAILURE);
}
