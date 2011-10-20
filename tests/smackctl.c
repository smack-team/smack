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
#define ACCESSES_D_PATH "/etc/smack/accesses.d"
#define PATH_SIZE 1000

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

static int apply(void)
{
	struct stat sbuf;
	DIR *dir;
	struct dirent *ent;
	char pathbuf[PATH_SIZE];

	if (is_smackfs_mounted() != 1) {
		fprintf(stderr, "ERROR: SmackFS is not mounted.\n");
		return -1;
	}

	if (clear())
		return -1;

	if (stat("/etc/smack/accesses", &sbuf) && errno != ENOENT) {
		perror("stat");
		clear();
		return -1;
	} else if (errno == 0 && apply_rules("/etc/smack/accesses", 0)) {
		clear();
		return -1;
	}

	if (stat(ACCESSES_D_PATH, &sbuf) && errno != ENOENT) {
		perror("stat");
		clear();
		return -1;
	} else if (errno == 0) {
		errno = 0;
		dir = opendir(ACCESSES_D_PATH);
		if (dir == NULL) {
			perror("opendir");
			clear();
			return -1;
		}

		for (;;) {
			errno = 0;
			ent = readdir(dir);
			if (ent == NULL) {
				closedir(dir);
				if (errno) {
					perror("readdir");
					clear();
					return -1;
				}
				break;
			}

			snprintf(pathbuf, PATH_SIZE, "%s/%s", ACCESSES_D_PATH,
				 ent->d_name);

			if (stat(pathbuf, &sbuf)) {
				perror("stat");
				closedir(dir);
				clear();
				return -1;
			}

			if (S_ISDIR(sbuf.st_mode))
				continue;

			if (apply_rules(pathbuf, 0)) {
				closedir(dir);
				clear();
				return -1;
			}
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

	if (apply_rules("/smack/load", SMACK_RULE_SET_APPLY_CLEAR))
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
		ret = statfs("/smack", &sfs);
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

