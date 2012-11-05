/*
 * This file is part of libsmack.
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
 * Jarkko Sakkinen <jarkko.sakkinen@intel.com>
 * Brian McGillion <brian.mcgillion@intel.com>
 */

#include "common.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <sys/smack.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define SMACK_MAGIC 0x43415d53

static int apply_rules_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);
static int apply_cipso_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);

int is_smackfs_mounted(void)
{
	struct statfs sfs;
	int ret;
	const char * smack_mnt;

	smack_mnt = smack_smackfs_path();
	if (!smack_mnt) {
		errno = EFAULT;
		return -1;
	}

	do {
		ret = statfs(smack_mnt, &sfs);
	} while (ret < 0 && errno == EINTR);

	if (ret)
		return -1;

	if (sfs.f_type == SMACK_MAGIC)
		return 1;

	return 0;
}

int clear(void)
{
	int fd;
	int ret;
	const char * smack_mnt;
	char path[PATH_MAX];

	smack_mnt = smack_smackfs_path();
	if (!smack_mnt) {
		errno = EFAULT;
		return -1;
	}

	if (is_smackfs_mounted() != 1)
		return -1;

	snprintf(path, sizeof path, "%s/load2", smack_mnt);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = apply_rules_file(fd, 1);
	close(fd);
	return ret;
}

int apply_rules(const char *path, int clear)
{
	struct stat sbuf;
	int fd;
	int ret;

	errno = 0;
	if (stat(path, &sbuf))
		return -1;

	if (S_ISDIR(sbuf.st_mode))
		return nftw(path, apply_rules_cb, 1, FTW_PHYS|FTW_ACTIONRETVAL);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = apply_rules_file(fd, clear);
	close(fd);
	return ret;
}

int apply_cipso(const char *path)
{
	struct stat sbuf;
	int fd;
	int ret;

	errno = 0;
	if (stat(path, &sbuf))
		return -1;

	if (S_ISDIR(sbuf.st_mode))
		return nftw(path, apply_cipso_cb, 1, FTW_PHYS|FTW_ACTIONRETVAL);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = apply_cipso_file(fd);
	close(fd);
	return ret;
}

int apply_rules_file(int fd, int clear)
{
	struct smack_accesses *rules = NULL;
	int ret = 0;

	if (smack_accesses_new(&rules))
		return -1;

	if (smack_accesses_add_from_file(rules, fd)) {
		smack_accesses_free(rules);
		return -1;
	}

	if (!clear)
		ret = smack_accesses_apply(rules);
	else
		ret = smack_accesses_clear(rules);

	smack_accesses_free(rules);

	return ret;
}

int apply_cipso_file(int fd)
{
	struct smack_cipso *cipso = NULL;
	int ret;

	cipso = smack_cipso_new(fd);
	if (cipso == NULL)
		return -1;

	ret = smack_cipso_apply(cipso);
	smack_cipso_free(cipso);
	if (ret)
		return -1;

	return 0;
}

static int apply_rules_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	int fd;
	int ret;

	if (typeflag == FTW_D)
		return ftwbuf->level ? FTW_SKIP_SUBTREE : FTW_CONTINUE;
	else if (typeflag != FTW_F)
		return FTW_STOP;

	fd = open(fpath, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = apply_rules_file(fd, 0) ? FTW_STOP : FTW_CONTINUE;
	close(fd);
	return ret;
}

static int apply_cipso_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	int fd;
	int ret;

	if (typeflag == FTW_D)
		return ftwbuf->level ? FTW_SKIP_SUBTREE : FTW_CONTINUE;
	else if (typeflag != FTW_F)
		return FTW_STOP;

	fd = open(fpath, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = apply_rules_file(fd, 0) ? FTW_STOP : FTW_CONTINUE;
	close(fd);
	return ret;
}
