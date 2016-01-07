/*
 * chsmack - Set smack attributes on files
 *
 * Copyright (C) 2011 Nokia Corporation.
 * Copyright (C) 2011, 2012, 2013 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <sys/smack.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <libgen.h>
#include "config.h"

static const char usage[] =
	"Usage: %s [options] <path>\n"
	"options:\n"  
	" -v --version         output version information and exit\n"
	" -h --help            output usage information and exit\n"
	" -a --access          set/remove "XATTR_NAME_SMACK"\n"
	" -e --exec            set/remove "XATTR_NAME_SMACKEXEC"\n"
	" -m --mmap            set/remove "XATTR_NAME_SMACKMMAP"\n"
	" -t --transmute       set/remove "XATTR_NAME_SMACKTRANSMUTE"\n"
	" -d --remove          tell to remove the attribute\n"
	" -L --dereference     tell to follow the symbolic links\n"
	" -D --drop            remove unset attributes\n"
	" -A --drop-access     remove "XATTR_NAME_SMACK"\n"
	" -E --drop-exec       remove "XATTR_NAME_SMACKEXEC"\n"
	" -M --drop-mmap       remove "XATTR_NAME_SMACKMMAP"\n"
	" -T --drop-transmute  remove "XATTR_NAME_SMACKTRANSMUTE"\n"
;

static const char shortoptions[] = "vha::e::m::tdLDAEMT";
static struct option options[] = {
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{"access", optional_argument, 0, 'a'},
	{"exec", optional_argument, 0, 'e'},
	{"mmap", optional_argument, 0, 'm'},
	{"transmute", no_argument, 0, 't'},
	{"dereference", no_argument, 0, 'L'},
	{"drop", no_argument, 0, 'D'},
	{"drop-access", no_argument, 0, 'A'},
	{"drop-exec", no_argument, 0, 'E'},
	{"drop-mmap", no_argument, 0, 'M'},
	{"drop-transmute", no_argument, 0, 'T'},
	{"remove", no_argument, 0, 'd'},
	{NULL, 0, 0, 0}
};

/* enumeration for state of flags */
enum state {
	unset    = 0,
	positive = 1,
	negative = 2
};

/* structure for recording options of label and their init */
struct labelset {
	enum state isset;  /* how is it set */
	const char *value; /* value of the option set if any or NULL else */
};

/* get the option for the given char */
static struct option *option_by_char(int car)
{
	struct option *result = options;
	while (result->name != NULL && result->val != car)
		result++;
	return result;
}

/* modify attributes of a file */
static void modify_file(const char *path, struct labelset *ls,
						const char *attr, int follow)
{
	int rc;
	switch (ls->isset) {
	case positive:
		rc = smack_set_label_for_path(path, attr, follow, ls->value);
		if (rc < 0)
			perror(path);
		break;
	case negative:
		rc = smack_remove_label_for_path(path, attr, follow);
		if (rc < 0 && errno != ENODATA)
			perror(path);
		break;
	}
}

/* modify transmutation of a file */
static void modify_transmute(const char *path, enum state isset, int follow)
{
	struct stat st;
	int rc;
	switch (isset) {
	case positive:
		rc = follow ?  stat(path, &st) : lstat(path, &st);
		if (rc < 0)
			perror(path);
		else if (!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "%s: transmute: not a directory\n",
				path);
		}
		else {
			rc = smack_set_label_for_path(path,
				XATTR_NAME_SMACKTRANSMUTE, follow, "TRUE");
			if (rc < 0)
				perror(path);
		}
		break;
	case negative:
		rc = smack_remove_label_for_path(path,
					XATTR_NAME_SMACKTRANSMUTE, follow);
		if (rc < 0 && errno != ENODATA)
			perror(path);
		break;
	}
}

/* main */
int main(int argc, char *argv[])
{
	struct labelset access_set = { unset, NULL }; /* for option "access" */
	struct labelset exec_set = { unset, NULL }; /* for option "exec" */
	struct labelset mmap_set = { unset, NULL }; /* for option "mmap" */

	struct labelset *labelset;
	char *label;

	enum state delete_flag = unset;
	enum state follow_flag = unset;
	enum state transmute_flag = unset;
	int modify = 0;
	int rc;
	int c;
	int i;

	/* scan options without argument */
	while ((c = getopt_long(argc, argv, shortoptions, options, NULL)) != -1) {

		switch (c) {
			case 'a':
			case 'e':
			case 'm':
				/* greedy on optional arguments */
				if (optarg == NULL && argv[optind] != NULL 
						&& argv[optind][0] != '-') {
					optind++;
				}
				break;
			case 'A':
				if (access_set.isset != unset)
					fprintf(stderr, "%s: %s: option set many times.\n",
							basename(argv[0]), option_by_char(c)->name);
				access_set.isset = negative;
				modify = 1;
				break;
			case 'E':
				if (exec_set.isset != unset)
					fprintf(stderr, "%s: %s: option set many times.\n",
							basename(argv[0]), option_by_char(c)->name);
				exec_set.isset = negative;
				modify = 1;
				break;
			case 'M':
				if (mmap_set.isset != unset)
					fprintf(stderr, "%s: %s: option set many times.\n",
							basename(argv[0]), option_by_char(c)->name);
				mmap_set.isset = negative;
				modify = 1;
				break;
			case 'T':
				if (transmute_flag != unset)
					fprintf(stderr, "%s: %s: option set many times.\n",
							basename(argv[0]), option_by_char(c)->name);
				transmute_flag = negative;
				modify = 1;
				break;
			case 't':
				if (transmute_flag != unset)
					fprintf(stderr, "%s: %s: option set many times.\n",
							basename(argv[0]), option_by_char(c)->name);
				transmute_flag = positive;
				modify = 1;
				break;
			case 'd':
				if (delete_flag == negative) {
					fprintf(stderr, "%s: %s: opposed to previous option.\n",
							basename(argv[0]), option_by_char(c)->name);
					exit(1);
				}
				if (delete_flag != unset)
					fprintf(stderr, "%s: %s: option set many times.\n",
							basename(argv[0]), option_by_char(c)->name);
				delete_flag = positive;
				break;
			case 'D':
				if (delete_flag == positive) {
					fprintf(stderr, "%s: %s: opposed to previous option.\n",
							basename(argv[0]), option_by_char(c)->name);
					exit(1);
				}
				if (delete_flag != unset)
					fprintf(stderr, "%s: %s: option set many times.\n",
							basename(argv[0]), option_by_char(c)->name);
				delete_flag = negative;
				break;
			case 'L':
				if (follow_flag != unset)
					fprintf(stderr, "%s: %s: option set many times.\n",
							basename(argv[0]), option_by_char(c)->name);
				follow_flag = positive;
				break;
			case 'v':
				printf("%s (libsmack) version " PACKAGE_VERSION "\n",
				       basename(argv[0]));
				exit(0);
			case 'h':
				printf(usage, basename(argv[0]));
				exit(0);
			default:
				printf(usage, basename(argv[0]));
				exit(1);
		}
	}
	if (delete_flag == positive && transmute_flag != unset)
		transmute_flag = negative;

	/* scan options with argument (possibly) */
	optind = 1;
	while ((c = getopt_long(argc, argv, shortoptions, options, NULL)) != -1) {

		switch (c) {
			case 'a':
				labelset = &access_set;
				break;
			case 'e':
				labelset = &exec_set;
				break;
			case 'm':
				labelset = &mmap_set;
				break;
			default:
				continue;
		}

		if (labelset->isset != unset) {
			fprintf(stderr, "%s: %s: option set many times.\n",
				basename(argv[0]), option_by_char(c)->name);
			exit(1);
		}
		/* greedy on optional arguments */
		if (optarg == NULL && argv[optind] != NULL && argv[optind][0] != '-') {
			optarg = argv[optind++];
		}
		if (optarg == NULL) {
			if (delete_flag != positive) {
				fprintf(stderr, "%s: %s: requires a label when setting.\n",
					basename(argv[0]), option_by_char(c)->name);
				exit(1);
			}
		}
		else if (delete_flag == positive) {
			fprintf(stderr, "%s: %s: requires no label when deleting.\n",
				basename(argv[0]), option_by_char(c)->name);
			exit(1);
		}
		else if (strnlen(optarg, SMACK_LABEL_LEN + 1) == SMACK_LABEL_LEN + 1) {
			fprintf(stderr, "%s: %s: \"%s\" exceeds %d characters.\n",
				basename(argv[0]), option_by_char(c)->name, optarg,
				 SMACK_LABEL_LEN);
			exit(1);
		}
		else if (smack_label_length(optarg) < 0) {
			fprintf(stderr, "%s: %s: \"%s\" is an invalid Smack label.\n",
				basename(argv[0]), option_by_char(c)->name, optarg);
			exit(1);
		}
		labelset->isset = delete_flag == positive ? negative : positive;
		labelset->value = optarg;
		modify = 1;
	}

	/* update states */
	if (delete_flag == negative) {
		/* remove unset attributes */
		if (access_set.isset == unset)
			access_set.isset = negative;
		if (exec_set.isset == unset)
			exec_set.isset = negative;
		if (mmap_set.isset == unset)
			mmap_set.isset = negative;
		if (transmute_flag == unset)
			transmute_flag = negative;
	}
	else if (delete_flag == positive && !modify) {
		access_set.isset = negative;
		exec_set.isset = negative;
		mmap_set.isset = negative;
		transmute_flag = negative;
		modify = 1;
	}

	/* modifying label of files */
	if (modify) {
		for (i = optind; i < argc; i++) {
			modify_file(argv[i], &access_set, XATTR_NAME_SMACK,
								follow_flag);
			modify_file(argv[i], &exec_set, XATTR_NAME_SMACKEXEC,
								follow_flag);
			modify_file(argv[i], &mmap_set, XATTR_NAME_SMACKMMAP,
								follow_flag);
			modify_transmute(argv[i], transmute_flag, follow_flag);
		}
	}

	/* listing label of files */
	else {
		for (i = optind; i < argc; i++) {

			/* Print file path. */
			printf("%s", argv[i]);

			errno = 0;
			rc = (int)smack_new_label_from_path(argv[i],
				XATTR_NAME_SMACK, follow_flag, &label);
			if (rc > 0) {
				printf(" access=\"%s\"", label);
				free(label);
			} else if (errno != 0) {
				printf(": %s", strerror(errno));
			}

			rc = (int)smack_new_label_from_path(argv[i],
				XATTR_NAME_SMACKEXEC, follow_flag, &label);
			if (rc > 0) {
				printf(" execute=\"%s\"", label);
				free(label);
			}

			rc = (int)smack_new_label_from_path(argv[i],
				XATTR_NAME_SMACKMMAP, follow_flag, &label);
			if (rc > 0) {
				printf(" mmap=\"%s\"", label);
				free(label);
			}

			rc = (int)smack_new_label_from_path(argv[i],
				XATTR_NAME_SMACKTRANSMUTE, follow_flag, &label);
			if (rc > 0) {
				printf(" transmute=\"%s\"", label);
				free(label);
			}

			printf("\n");
		}
	}

	exit(0);
}
