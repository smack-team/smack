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
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/smack.h>

typedef int (*add_func)(void *smack, int fd);

int clear(void)
{
	int ret;
	const char * smack_mnt;
	char path[PATH_MAX];

	smack_mnt = smack_smackfs_path();
	if (!smack_mnt)
		return -1;

	snprintf(path, sizeof path, "%s/load2", smack_mnt);
	ret = apply_rules(path, 1);
	return ret;
}

static int apply_path(const char *path, void *smack, add_func func)
{
	DIR *dir;
	struct dirent *dent;
	int dfd;
	int fd;
	int ret = 0;

	if (path == NULL) {
		ret = func(smack, STDIN_FILENO);
		if (ret < 0)
			fputs("Reading from STDIN failed.\n", stderr);
		return ret;
	}

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
				ret = -1;
				break;
			}

			ret = func(smack, fd);
			close(fd);
			if (ret < 0) {
				fprintf(stderr, "Reading from '%s' failed.\n",
					path);
				break;
			}
		}

		closedir(dir);
		return ret;
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

	ret = func(smack, fd);
	if (ret < 0)
		fprintf(stderr, "Reading from '%s' failed.\n", path);
	close(fd);
	return ret;
}

int apply_rules(const char *path, int clear)
{
	struct smack_accesses *rules = NULL;
	int ret;

	if (smack_accesses_new(&rules)) {
		fputs("Out of memory.\n", stderr);
		return -1;
	}

	ret = apply_path(path, rules, (add_func) smack_accesses_add_from_file);
	if (ret) {
		smack_accesses_free(rules);
		return ret;
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
	return 0;
}

int apply_cipso(const char *path)
{
	struct smack_cipso *cipso = NULL;
	int ret;

	ret = smack_cipso_new(&cipso);
	if (ret) {
		fputs("Out of memory.\n", stderr);
		return -1;
	}

	ret = apply_path(path, cipso, (add_func) smack_cipso_add_from_file);
	if (ret) {
		smack_cipso_free(cipso);
		return ret;
	}

	ret = smack_cipso_apply(cipso);
	smack_cipso_free(cipso);
	if (ret) {
		fputs("Applying CIPSO failed.\n", stderr);
		return -1;
	}

	return 0;
}
