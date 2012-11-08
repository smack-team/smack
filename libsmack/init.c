/*
 * This file is part of libsmack. Derived from libselinux/src/init.c.
 *
 * Copyright (C) 2012 Intel Corporation
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
 * Passion Zhao <passion.zhao@intel.com>
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

/*
 *  * smackfs magic number
 *   */
#define SMACK_MAGIC     0x43415d53 /* "SMAC" */

/* smack file system type */
#define SMACKFS "smackfs"

#define SMACKFSMNT "/sys/fs/smackfs/"
#define OLDSMACKFSMNT "/smack"

char *smack_mnt = NULL;

void set_smackmnt(const char *mnt)
{
	smack_mnt = strdup(mnt);
}

/* Verify the mount point for smack file system has a smackfs.
 * If the file system:
 * Exist,
 * Is mounted with an smack file system,
 * The file system is read/write
 * then set this as the default file system.
 */
static int verify_smackmnt(const char *mnt)
{
	struct statfs sfbuf;
	int rc;

	do {
		rc = statfs(mnt, &sfbuf);
	} while (rc < 0 && errno == EINTR);

	if (rc == 0) {
		if ((uint32_t)sfbuf.f_type == (uint32_t)SMACK_MAGIC) {
			struct statvfs vfsbuf;
			rc = statvfs(mnt, &vfsbuf);
			if (rc == 0) {
				if (!(vfsbuf.f_flag & ST_RDONLY)) {
					set_smackmnt(mnt);
				}
				return 0;
			}
		}
	}

	return -1;
}

int smackfs_exists(void)
{
	int exists = 0;
	FILE *fp = NULL;
	char *buf = NULL;
	size_t len;
	ssize_t num;

	fp = fopen("/proc/filesystems", "r");
	if (!fp)
		return 1; /* Fail as if it exists */

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

static void init_smackmnt(void)
{
	char *buf=NULL, *p;
	FILE *fp=NULL;
	size_t len;
	ssize_t num;

	if (smack_mnt)
		return;

	if (verify_smackmnt(SMACKFSMNT) == 0) 
		return;

	if (verify_smackmnt(OLDSMACKFSMNT) == 0) 
		return;

	/* Drop back to detecting it the long way. */
	if (!smackfs_exists())
		goto out;

	/* At this point, the usual spot doesn't have an smackfs so
	 * we look around for it */
	fp = fopen("/proc/mounts", "r");
	if (!fp)
		goto out;

	__fsetlocking(fp, FSETLOCKING_BYCALLER);
	while ((num = getline(&buf, &len, fp)) != -1) {
		char *tmp;
		p = strchr(buf, ' ');
		if (!p)
			goto out;
		p++;

		tmp = strchr(p, ' ');
		if (!tmp)
			goto out;

		if (!strncmp(tmp + 1, SMACKFS" ", strlen(SMACKFS)+1)) {
			*tmp = '\0';
			break;
		}
	}

	/* If we found something, dup it */
	if (num > 0)
		verify_smackmnt(p);

      out:
	free(buf);
	if (fp)
		fclose(fp);
	return;
}

void fini_smackmnt(void)
{
	free(smack_mnt);
	smack_mnt = NULL;
}

static void init_lib(void) __attribute__ ((constructor));
static void init_lib(void)
{
	init_smackmnt();
}

static void fini_lib(void) __attribute__ ((destructor));
static void fini_lib(void)
{
	fini_smackmnt();
}
