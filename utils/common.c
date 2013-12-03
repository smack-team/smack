/*
 * This file is part of libsmack.
 *
 * Copyright (C) 2011, 2012, 2013 Intel Corporation
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

#include "common.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <string.h>
#include <sys/smack.h>

#define SMACK_MAGIC 0x43415d53

static int apply_cipso_cb(const char *fpath, const struct stat *sb,
			  int typeflag, struct FTW *ftwbuf);

int clear(void)
{
	int fd;
	int ret;
	const char * smack_mnt;
	char path[PATH_MAX];

	smack_mnt = smack_smackfs_path();
	if (!smack_mnt)
		return -1;

	snprintf(path, sizeof path, "%s/load2", smack_mnt);
	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open() failed for '%s' : %s\n", path,
			strerror(errno));
		return -1;
	}

	ret = apply_rules_file(path, fd, 1);
	close(fd);
	return ret;
}

int apply_rules(const char *path, int clear)
{
	DIR *dir;
	struct dirent *dent;
	int dfd;
	int fd;
	int ret;

	dir = opendir(path);
	if (dir) {
		for (dfd = dirfd(dir), dent = readdir(dir);
		     dent != NULL; dent = readdir(dir)) {
			if (dent->d_type == DT_DIR)
				continue;

			if (dent->d_type == DT_UNKNOWN) {
				fprintf(stderr, "'%s' file type is unknown\n",
					dent->d_name);
				closedir(dir);
				return -1;
			}

			if (dent->d_type != DT_REG) {
				fprintf(stderr, "'%s' is a non-regular file\n",
					dent->d_name);
				closedir(dir);
				return -1;
			}

			fd = openat(dfd, dent->d_name, O_RDONLY);
			if (fd == -1) {
				fprintf(stderr, "openat() failed for '%s' : %s\n",
					dent->d_name, strerror(errno));
				closedir(dir);
				return -1;
			}

			ret = apply_rules_file(dent->d_name, fd, clear);
			close(fd);
			if (ret < 0) {
				closedir(dir);
				return -1;
			}
		}

		closedir(dir);
		return 0;
	}

	if (errno != ENOTDIR) {
		fprintf(stderr, "opendir() failed for '%s' : %s\n",
			path, strerror(errno));
		return -1;
	}

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open() failed for '%s' : %s\n", path,
			strerror(errno));
		return -1;
	}

	ret = apply_rules_file(path, fd, clear);
	close(fd);
	return ret;
}

int apply_cipso(const char *path)
{
	struct stat sbuf;
	int fd;
	int ret;

	if (stat(path, &sbuf)) {
		fprintf(stderr, "stat() failed for '%s' : %s\n", path,
			strerror(errno));
		return -1;
	}

	if (S_ISDIR(sbuf.st_mode))
		return nftw(path, apply_cipso_cb, 1, FTW_PHYS|FTW_ACTIONRETVAL);

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open() failed for '%s' : %s\n", path,
			strerror(errno));
		return -1;
	}

	ret = apply_cipso_file(path, fd);
	close(fd);
	return ret;
}

int apply_rules_file(const char *path, int fd, int clear)
{
	struct smack_accesses *rules = NULL;
	int ret = 0;

	if (smack_accesses_new(&rules))
		return -1;

	if (smack_accesses_add_from_file(rules, fd)) {
		smack_accesses_free(rules);
		if (path)
			fprintf(stderr, "Reading rules from '%s' failed.\n",
				path);
		else
			fputs("Reading rules from STDIN failed.\n", stderr);
		return -1;
	}

	if (clear) {
		ret = smack_accesses_clear(rules);
		if (ret)
			fputs("Clearing rules failed.\n", stderr);
	} else {
		ret = smack_accesses_apply(rules);
		if (ret)
			fputs("Applying rules failed.\n", stderr);
	}

	smack_accesses_free(rules);
	return ret;
}

int apply_cipso_file(const char *path, int fd)
{
	struct smack_cipso *cipso = NULL;
	int ret;

	ret = smack_cipso_new(&cipso);
	if (ret)
		return -1;

	ret = smack_cipso_add_from_file(cipso, fd);
	if (ret) {
		if (path)
			fprintf(stderr, "Reading CIPSO from '%s' failed.\n",
				path);
		else
			fputs("Reading CIPSO from STDIN failed.\n",
			      stderr);
		smack_cipso_free(cipso);
		return -1;
	}

	ret = smack_cipso_apply(cipso);
	smack_cipso_free(cipso);
	if (ret) {
		fprintf(stderr, "Applying CIPSO failed.\n",
			path);
		return -1;
	}

	return 0;
}

static int apply_cipso_cb(const char *fpath, const struct stat *sb,
			  int typeflag, struct FTW *ftwbuf)
{
	int fd;
	int ret;

	if (typeflag == FTW_D)
		return ftwbuf->level ? FTW_SKIP_SUBTREE : FTW_CONTINUE;
	else if (typeflag != FTW_F)
		return FTW_STOP;

	fd = open(fpath, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "open() failed for '%s' : %s\n", fpath,
			strerror(errno));
		return -1;
	}

	ret = apply_cipso_file(fpath, fd) ? FTW_STOP : FTW_CONTINUE;
	close(fd);
	return ret;
}
