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

#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <alloca.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libsmack.h>
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
#define CIPSO_PATH "/etc/smack/cipso"
#define CIPSO_D_PATH "/etc/smack/cipso.d"

#define LABEL_LEN 23
#define CAT_MAX_COUNT 240
#define CAT_MAX_VALUE 63
#define LEVEL_MAX 255
#define NUM_LEN 4

#define CIPSO_POS(i)   (LABEL_LEN + 1 + NUM_LEN + NUM_LEN + i * NUM_LEN)
#define CIPSO_MAX_SIZE CIPSO_POS(CAT_MAX_COUNT)

#define BUF_SIZE 512

struct cipso_mapping {
	char label[LABEL_LEN + 1];
	int cats[CAT_MAX_VALUE];
	int ncats;
	int level;
	struct cipso_mapping *next;
};

struct cipso {
	struct cipso_mapping *first;
	struct cipso_mapping *last;
};

static int apply(void);
static int clear(void);
static int status(void);
static int is_smackfs_mounted(void);
static int apply_rules(const char *path, int flags);
static int apply_rules_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);
static int apply_cipso(const char *path);
static int apply_cipso_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf);

static struct cipso *cipso_new(const char *path);
static void cipso_free(struct cipso *cipso);
static int cipso_apply(struct cipso *cipso);

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
		if (nftw(ACCESSES_D_PATH, apply_rules_cb, 1, FTW_PHYS|FTW_ACTIONRETVAL)) {
			perror("nftw");
			clear();
			return -1;
		}
	}

	errno = 0;
	if (stat(CIPSO_PATH, &sbuf) && errno != ENOENT) {
		perror("stat");
		clear();
		return -1;
	}

	if (!errno) {
		if (apply_cipso(CIPSO_PATH)) {
			clear();
			return -1;
		}
	}

	errno = 0;
	if (stat(CIPSO_D_PATH, &sbuf) && errno != ENOENT) {
		perror("stat");
		clear();
		return -1;
	}

	if (!errno) {
		if (nftw(CIPSO_D_PATH, apply_cipso_cb, 1, FTW_PHYS|FTW_ACTIONRETVAL)) {
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
	struct smack_accesses *rules = NULL;
	int fd = 0;
	int ret = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	rules = smack_accesses_new(fd);
	close(fd);
	if (rules == NULL) {
		perror("smack_accesses_new");
		return -1;
	}

	ret = smack_accesses_apply(rules, flags);
	smack_accesses_free(rules);
	if (ret) {
		perror("smack_accesses_apply");
		return -1;
	}

	return 0;
}

static int apply_rules_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	if (typeflag == FTW_D)
		return ftwbuf->level ? FTW_SKIP_SUBTREE : FTW_CONTINUE;
	else if (typeflag != FTW_F)
		return FTW_STOP;
	return apply_rules(fpath, 0) ? FTW_STOP : FTW_CONTINUE;
}

static int apply_cipso(const char *path)
{
	struct cipso *cipso = NULL;
	int ret;

	cipso = cipso_new(path);
	if (cipso == NULL) {
		perror("smack_cipso_new");
		return -1;
	}

	ret = cipso_apply(cipso);
	cipso_free(cipso);
	if (ret) {
		perror("cipso_apply");
		return -1;
	}

	return 0;
}

static int apply_cipso_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
	if (typeflag == FTW_D)
		return ftwbuf->level ? FTW_SKIP_SUBTREE : FTW_CONTINUE;
	else if (typeflag != FTW_F)
		return FTW_STOP;
	return apply_cipso(fpath) ? FTW_STOP : FTW_CONTINUE;
}

static struct cipso *cipso_new(const char *path)
{
	struct cipso *cipso = NULL;
	struct cipso_mapping *mapping = NULL;
	FILE *file = NULL;
	char buf[BUF_SIZE];
	char *label, *level, *cat, *ptr;
	long int val;
	int i;

	file = fopen(path, "r");
	if (file == NULL)
		return NULL;

	cipso = calloc(sizeof(struct cipso), 1);
	if (cipso == NULL) {
		fclose(file);
		return NULL;
	}

	while (fgets(buf, BUF_SIZE, file) != NULL) {
		mapping = calloc(sizeof(struct cipso_mapping), 1);
		if (mapping == NULL)
			goto err_out;

		label = strtok_r(buf, " \t\n", &ptr);
		level = strtok_r(NULL, " \t\n", &ptr);
		cat = strtok_r(NULL, " \t\n", &ptr);
		if (label == NULL || cat == NULL || level == NULL ||
		    strlen(label) > LABEL_LEN) {
			errno = EINVAL;
			goto err_out;
		}

		strcpy(mapping->label, label);

		errno = 0;
		val = strtol(level, NULL, 10);
		if (errno)
			goto err_out;

		if (val < 0 || val > LEVEL_MAX) {
			errno = ERANGE;
			goto err_out;
		}

		mapping->level = val;

		for (i = 0; i < CAT_MAX_COUNT && cat != NULL; i++) {
			errno = 0;
			val = strtol(cat, NULL, 10);
			if (errno)
				goto err_out;

			if (val < 0 || val > CAT_MAX_VALUE) {
				errno = ERANGE;
				goto err_out;
			}

			mapping->cats[i] = val;

			cat = strtok_r(NULL, " \t\n", &ptr);
		}

		mapping->ncats = i;

		if (cipso->first == NULL) {
			cipso->first = cipso->last = mapping;
		} else {
			cipso->last->next = mapping;
			cipso->last = mapping;
		}
	}

	if (ferror(file))
		goto err_out;

	fclose(file);
	return cipso;
err_out:
	fclose(file);
	cipso_free(cipso);
	free(mapping);
	return NULL;
}

static void cipso_free(struct cipso *cipso)
{
	if (cipso == NULL)
		return;

	struct cipso_mapping *mapping = cipso->first;
	struct cipso_mapping *next_mapping = NULL;

	while (mapping != NULL) {
		next_mapping = mapping->next;
		free(mapping);
		mapping = next_mapping;
	}
}

static int cipso_apply(struct cipso *cipso)
{
	struct cipso_mapping *m = NULL;
	char buf[CIPSO_MAX_SIZE];
	int fd;
	int i;

	fd = open(SMACKFS_MNT "/cipso", O_WRONLY);
	if (fd < 0)
		return -1;

	for (m = cipso->first; m != NULL; m = m->next) {
		sprintf(buf, "%-23s ", m->label);
		sprintf(&buf[LABEL_LEN + 1], "%-4d", m->level);
		sprintf(&buf[LABEL_LEN + 1 + NUM_LEN], "%-4d", m->ncats);

		for (i = 0; i < m->ncats; i++)
			sprintf(&buf[CIPSO_POS(i)], "%-4d", m->cats[i]);

		if (write(fd, buf, strlen(buf)) < 0) {
			close(fd);
			return -1;
		}
	}

	close(fd);
	return 0;
}

