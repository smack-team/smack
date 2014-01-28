/*
 * This file is part of libsmack. Derived from libselinux/src/init.c.
 *
 * Copyright (C) 2012, 2013 Intel Corporation
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
 */

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <dlfcn.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <stdint.h>
#include <limits.h>
#include <pthread.h>

#define SMACK_MAGIC	0x43415d53 /* "SMAC" */
#define SMACKFS		"smackfs"
#define SMACKFSMNT	"/sys/fs/smackfs/"
#define OLDSMACKFSMNT	"/smack"

char *smackfs_mnt = NULL;
int smackfs_mnt_dirfd = -1;

static pthread_mutex_t smackfs_mnt_lock = PTHREAD_MUTEX_INITIALIZER;

static int verify_smackfs_mnt(const char *mnt);
static int smackfs_exists(void);

int init_smackfs_mnt(void)
{
	char *buf = NULL;
	char *startp;
	char *endp;
	FILE *fp = NULL;
	size_t len;
	ssize_t num;
	int ret = 0;

	if (smackfs_mnt ||
	    verify_smackfs_mnt(SMACKFSMNT) == 0 ||
	    verify_smackfs_mnt(OLDSMACKFSMNT) == 0)
		return 0;

	if (!smackfs_exists())
		return -1;

	fp = fopen("/proc/mounts", "r");
	if (!fp)
		return -1;

	__fsetlocking(fp, FSETLOCKING_BYCALLER);
	while ((num = getline(&buf, &len, fp)) != -1) {
		startp = strchr(buf, ' ');
		if (!startp) {
			ret = -1;
			break;
		}
		startp++;

		endp = strchr(startp, ' ');
		if (!endp) {
			ret = -1;
			break;
		}

		if (!strncmp(endp + 1, SMACKFS" ", strlen(SMACKFS) + 1)) {
			*endp = '\0';
			ret = verify_smackfs_mnt(startp);
			break;
		}
	}

	free(buf);
	fclose(fp);
	return ret;
}

static int verify_smackfs_mnt(const char *mnt)
{
	struct statfs sfbuf;
	int rc;
	int fd;

	fd = open(mnt, O_RDONLY, 0);
	if (fd < 0)
		return -1;

	do {
		rc = fstatfs(fd, &sfbuf);
	} while (rc < 0 && errno == EINTR);

	if (rc == 0) {
		if ((uint32_t) sfbuf.f_type == (uint32_t) SMACK_MAGIC) {
			struct statvfs vfsbuf;
			rc = statvfs(mnt, &vfsbuf);
			if (rc == 0) {
				if (!(vfsbuf.f_flag & ST_RDONLY)) {
					pthread_mutex_lock(&smackfs_mnt_lock);
					if (smackfs_mnt_dirfd == -1) {
						smackfs_mnt = strdup(mnt);
						smackfs_mnt_dirfd = fd;
					} else {
						/* Some other thread won the race. */
						close(fd);
					}
					pthread_mutex_unlock(&smackfs_mnt_lock);
					return 0;
				}
			}
		}
	}

	close(fd);
	return -1;
}

static int smackfs_exists(void)
{
	int exists = 0;
	FILE *fp = NULL;
	char *buf = NULL;
	size_t len;
	ssize_t num;

	/* Fail as SmackFS would exist since we are checking mounts after
	 * this.
	 */
	fp = fopen("/proc/filesystems", "r");
	if (!fp)
		return 1;

	__fsetlocking(fp, FSETLOCKING_BYCALLER);

	num = getline(&buf, &len, fp);
	while (num != -1) {
		if (strstr(buf, SMACKFS)) {
			exists = 1;
			break;
		}
		num = getline(&buf, &len, fp);
	}

	free(buf);
	fclose(fp);
	return exists;
}

static void fini_lib(void) __attribute__ ((destructor));
static void fini_lib(void)
{
	if (smackfs_mnt_dirfd >= 0)
		close(smackfs_mnt_dirfd);
	free(smackfs_mnt);
	smackfs_mnt = NULL;
}
