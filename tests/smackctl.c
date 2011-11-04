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
 */

#define __USE_XOPEN_EXTENDED 1
#define _GNU_SOURCE 1
#define __USE_GNU 1
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <alloca.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <smack.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#define SMACKFS_MAGIC 0x43415d53
#define SMACKFS_MNT "/smack"
#define ACCESSES_PATH "/etc/smack/accesses"
#define ACCESSES_D_PATH "/etc/smack/accesses.d"

static int apply(void);
static int clear(void);
static int status(void);
static int is_smackfs_mounted(void);
static int apply_rules(const char *path, int flags);

int main(int argc, char **argv)
{
	int a;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <action>\n", argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "apply")) {
		if (apply())
			return 1;
	} else if (!strcmp(argv[1], "clear")) {
		if (clear())
			return 1;
	} else if (!strcmp(argv[1], "status")) {
		if (status())
			return 1;
	} else {
		fprintf(stderr, "Uknown action: %s\n", argv[1]);
		return 1;
	}

	return 0;
}

static int apply_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	if (typeflag == FTW_D)
		return ftwbuf->level ? FTW_SKIP_SUBTREE : FTW_CONTINUE;
	else if (typeflag != FTW_F)
		return FTW_STOP;
	return apply_rules(fpath, 0) ? FTW_STOP : FTW_CONTINUE;
}

static int apply(void)
{
	struct stat sbuf;

	if (is_smackfs_mounted() != 1) {
		fprintf(stderr, "ERROR: SmackFS is not mounted.\n");
		return -1;
	}

	if (clear())
		return -1;

	errno = 0;
	if (stat(ACCESSES_PATH, &sbuf) && errno != ENOENT) {
		perror("stat");
		clear();
		return -1;
	}

	if (!errno) {
		if (apply_rules(ACCESSES_PATH, 0)) {
			clear();
			return -1;
		}
	}

	errno = 0;
	if (stat(ACCESSES_D_PATH, &sbuf) && errno != ENOENT) {
		perror("stat");
		clear();
		return -1;
	}

	if (!errno) {
		if (nftw(ACCESSES_D_PATH, apply_cb, 1, FTW_PHYS|FTW_ACTIONRETVAL)) {
			perror("nftw");
			clear();
			return -1;
		}
	}

	return 0;
}

static int clear(void)
{
	if (is_smackfs_mounted() != 1) {
		fprintf(stderr, "ERROR: SmackFS is not mounted.\n");
		return -1;
	}

	if (apply_rules(SMACKFS_MNT "/load", SMACK_RULE_SET_APPLY_CLEAR))
		return -1;

	return 0;
}

static int status(void)
{
	int ret = is_smackfs_mounted();

	switch (ret) {
		case 1:
			printf("SmackFS is mounted.\n");
			return 0;
		case 0:
			printf("SmackFS is not mounted.\n");
			return 0;
		default:
			return -1;
	}
}

static int is_smackfs_mounted(void)
{
	struct statfs sfs;
	int ret;

	do {
		ret = statfs(SMACKFS_MNT, &sfs);
	} while (ret < 0 && errno == EINTR);

	if (ret) {
		perror("statfs");
		return -1;
	}

	if (sfs.f_type == SMACKFS_MAGIC)
		return 1;

	return 0;
}

static int apply_rules(const char *path, int flags)
{
	SmackRuleSet rules = NULL;
	int fd = 0;
	int ret = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	rules = smack_rule_set_new(fd);
	close(fd);
	if (rules == NULL) {
		perror("smack_rule_set_new");
		return -1;
	}

	ret = smack_rule_set_apply(rules, flags);
	smack_rule_set_free(rules);
	if (ret) {
		perror("smack_rule_set_apply");
		return -1;
	}

	return 0;
}

