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
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <fts.h>
#include <stdio.h>
#include <string.h>
#include <sys/smack.h>
#include <linux/limits.h>

#define SMACK_MAGIC 0x43415d53

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

static int fts_cmp(const FTSENT **s1, const FTSENT **s2)
{
	return strcoll((*s1)->fts_name, (*s2)->fts_name);
}

static int apply_files(const char *path, add_func func, void *smack)
{
	FTS *fts = NULL;
	FTSENT *ftsent;
	int fd;
	int ret = 0;
	const char *path_argv[] = {path, NULL};

	if (path == NULL) {
		ret = func(smack, STDIN_FILENO);
		if (ret < 0)
			fprintf(stderr, "Parsing from STDIN failed.\n");
		return ret;
	}

	fts = fts_open((char * const *) path_argv,
		FTS_PHYSICAL | FTS_NOSTAT, fts_cmp);

	if (fts == NULL) {
		fprintf(stderr, "fts_open() failed for '%s' : %s\n",
			path, strerror(errno));
		return -1;
	}

	while ((ftsent = fts_read(fts)) != NULL) {
		switch (ftsent->fts_info) {
		case FTS_DEFAULT:
		case FTS_NSOK:
		case FTS_SL:
		case FTS_F:
			fd = open(ftsent->fts_accpath, O_RDONLY);
			if (fd == -1) {
				fprintf(stderr, "open() failed for '%s' : %s\n",
					ftsent->fts_accpath, strerror(errno));
				ret = -1;
				goto out;
			}

			ret = func(smack, fd);
			close(fd);
			if (ret < 0) {
				fprintf(stderr, "Parsing from '%s' failed.\n",
					ftsent->fts_accpath);
				ret = -1;
				goto out;
			}
			break;
		case FTS_D:
			if (ftsent->fts_level > 0)
				fts_set(fts, ftsent, FTS_SKIP);
			break;
		case FTS_ERR:
			fprintf(stderr, "fts_read() failed : %s\n",
				strerror(ftsent->fts_errno));
			ret = -1;
			goto out;
		case FTS_DNR:
		case FTS_NS:
			fprintf(stderr, "fts_read() failed for '%s' : %s\n",
				ftsent->fts_accpath, strerror(ftsent->fts_errno));
			ret = -1;
			goto out;
		}
	}

out:
	fts_close(fts);
	return ret;

}

int apply_rules(const char *path, int clear)
{
	struct smack_accesses *rules = NULL;
	int ret;

	if (smack_accesses_new(&rules)) {
		fprintf(stderr, "Out of memory.\n");
		return -1;
	}

	ret = apply_files(path, (add_func) smack_accesses_add_from_file, rules);
	if (ret) {
		smack_accesses_free(rules);
		return ret;
	}

	if (clear) {
		ret = smack_accesses_clear(rules);
		if (ret)
			fprintf(stderr, "Clearing rules failed.\n");
	} else {
		ret = smack_accesses_apply(rules);
		if (ret)
			fprintf(stderr, "Applying rules failed.\n");
	}

	smack_accesses_free(rules);
	return ret;
}

int apply_cipso(const char *path)
{
	struct smack_cipso *cipso = NULL;
	int ret;

	if (smack_cipso_new(&cipso)) {
		fprintf(stderr, "Out of memory.\n");
		return -1;
	}

	ret = apply_files(path, (add_func) smack_cipso_add_from_file, cipso);
	if (ret) {
		smack_cipso_free(cipso);
		return ret;
	}

	ret = smack_cipso_apply(cipso);
	if (ret)
		fprintf(stderr, "Applying CIPSO failed.\n",
			path);

	smack_cipso_free(cipso);
	return ret;
}
