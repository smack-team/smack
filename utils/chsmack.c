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
#include <dirent.h>

#include "config.h"

static const char usage[] =
	"Usage: %s [options] <path>\n"
	"Options:\n"  
	" -v --version         output version information and exit\n"
	" -h --help            output usage information and exit\n"
	" -a --access          set "XATTR_NAME_SMACK"\n"
	" -e --exec            set "XATTR_NAME_SMACKEXEC"\n"
	" -m --mmap            set "XATTR_NAME_SMACKMMAP"\n"
	" -t --transmute       set "XATTR_NAME_SMACKTRANSMUTE"\n"
	" -L --dereference     tell to follow the symbolic links\n"
	" -D --drop            remove unset attributes\n"
	" -A --drop-access     remove "XATTR_NAME_SMACK"\n"
	" -E --drop-exec       remove "XATTR_NAME_SMACKEXEC"\n"
	" -M --drop-mmap       remove "XATTR_NAME_SMACKMMAP"\n"
	" -T --drop-transmute  remove "XATTR_NAME_SMACKTRANSMUTE"\n"
	" -r --recursive       list or modify also files in subdirectories\n"
	"Obsolete option:\n"
	" -d --remove          tell to remove the attribute\n"
;

static const char shortoptions[] = "vha::e::m::tdLDAEMTr";
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
	{"recursive", no_argument, 0, 'r'},
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

static struct labelset access_set = { unset, NULL }; /* for option "access" */
static struct labelset exec_set = { unset, NULL }; /* for option "exec" */
static struct labelset mmap_set = { unset, NULL }; /* for option "mmap" */
static enum state transmute_flag = unset; /* for option "transmute" */
static enum state follow_flag = unset; /* for option "dereference" */
static enum state recursive_flag = unset; /* for option "recursive" */

/* get the option for the given char */
static struct option *option_by_char(int car)
{
	struct option *result = options;
	while (result->name != NULL && result->val != car)
		result++;
	return result;
}

/* modify attributes of a file */
static void modify_prop(const char *path, struct labelset *ls, const char *attr)
{
	int rc;
	switch (ls->isset) {
	case positive:
		rc = smack_set_label_for_path(path, attr, follow_flag,
					      ls->value);
		if (rc < 0)
			perror(path);
		break;
	case negative:
		rc = smack_remove_label_for_path(path, attr, follow_flag);
		if (rc < 0 && errno != ENODATA)
			perror(path);
		break;
	}
}

/* modify transmutation of a directory */
static void modify_transmute(const char *path)
{
	struct stat st;
	int rc;
	switch (transmute_flag) {
	case positive:
		rc = follow_flag ? stat(path, &st) : lstat(path, &st);
		if (rc < 0)
			perror(path);
		else if (!S_ISDIR(st.st_mode)) {
			if (!recursive_flag) {
				fprintf(stderr,
					"%s: transmute: not a directory\n",
					path);
			}
		} else {
			rc = smack_set_label_for_path(path,
						      XATTR_NAME_SMACKTRANSMUTE,
						      follow_flag, "TRUE");
			if (rc < 0)
				perror(path);
		}
		break;
	case negative:
		rc = smack_remove_label_for_path(path,
						 XATTR_NAME_SMACKTRANSMUTE,
						 follow_flag);
		if (rc < 0 && errno != ENODATA)
			perror(path);
		break;
	}
}

/* modify the file (or directory) of path */
static void modify_file(const char *path)
{
	modify_prop(path, &access_set, XATTR_NAME_SMACK);
	modify_prop(path, &exec_set, XATTR_NAME_SMACKEXEC);
	modify_prop(path, &mmap_set, XATTR_NAME_SMACKMMAP);
	modify_transmute(path);
}

/* print the file (or directory) of path */
static void print_file(const char *path)
{
	ssize_t rc;
	char *label;
	int has_some_smack = 0;

	/* Print file path. */
	printf("%s", path);

	errno = 0;
	rc = smack_new_label_from_path(path, XATTR_NAME_SMACK, follow_flag,
				       &label);
	if (rc > 0) {
		printf(" access=\"%s\"", label);
		free(label);
		has_some_smack = 1;
	}

	rc = smack_new_label_from_path(path, XATTR_NAME_SMACKEXEC, follow_flag,
				       &label);
	if (rc > 0) {
		printf(" execute=\"%s\"", label);
		free(label);
		has_some_smack = 1;
	}

	rc = smack_new_label_from_path(path, XATTR_NAME_SMACKMMAP, follow_flag,
				       &label);
	if (rc > 0) {
		printf(" mmap=\"%s\"", label);
		free(label);
		has_some_smack = 1;
	}

	rc = smack_new_label_from_path(path, XATTR_NAME_SMACKTRANSMUTE,
				       follow_flag, &label);
	if (rc > 0) {
		printf(" transmute=\"%s\"", label);
		free(label);
		has_some_smack = 1;
	}

	printf(has_some_smack ? "\n" : ": No smack property found\n");
}

static void explore(const char *path, void (*fun)(const char*), int follow)
{
	struct stat st;
	int rc;
	char *file;
	size_t last, length, l;
	DIR *dir;
	struct dirent dent, *pent;

	/* type of the path */
	rc = (follow ? stat : lstat)(path ? path : ".", &st);
	if (rc < 0) {
		perror(path);
		return;
	}

	/* no a directory, skip */
	if (!S_ISDIR(st.st_mode))
		return;

	/* open the directory */
	dir = opendir(path ? path : ".");
	if (dir == NULL) {
		perror(path);
		return;
	}

	/* iterate ove the directory's entries */
	last = path ? strlen(path) : 0;
	length = last + 100;
	file = malloc(length);
	if (file == NULL) {
		fprintf(stderr, "error: out of memory.\n");
		exit(1);
	}
	if (last != 0) {
		memcpy(file, path, last);
		file[last++] = '/';
	}
	for (;;) {
		rc = readdir_r(dir, &dent, &pent);
		if (rc != 0 || pent == NULL) {
			if (rc)
				fprintf(stderr,
					"error: while scaning directory '%s'.\n",
					path ? path : ".");
			free(file);
			closedir(dir);
			return;
		}
		if (!strcmp(dent.d_name, ".") || !strcmp(dent.d_name, ".."))
			continue;
		l = strlen(dent.d_name);
		if (last + l >= length) {
			file = realloc(file, last + l + 20);
			if (file == NULL) {
				fprintf(stderr, "error: out of memory.\n");
				exit(1);
			}
			length = last + l + 20;
		}
		memcpy(file + last, dent.d_name, l + 1);
		fun(file);
		if (recursive_flag)
			explore(file, fun, 0);
	}
}

/* set the state to to */
static void set_state(enum state *to, enum state value, int car, int fatal)
{
	if (*to == unset)
		*to = value;
	else if (*to == value) {
		fprintf(stderr, "%s, option --%s or -%c already set.\n",
			fatal ? "error" : "warning",
			option_by_char(car)->name, option_by_char(car)->val);
		if (fatal)
			exit(1);
	} else {
		fprintf(stderr, "error, option --%s or -%c opposite to an "
			"option already set.\n",
			option_by_char(car)->name, option_by_char(car)->val);
		exit(1);
	}
}

/* main */
int main(int argc, char *argv[])
{
	struct labelset *labelset;

	void (*fun)(const char*);
	enum state delete_flag = unset;
	enum state svalue;
	int modify = 0;
	int rc;
	int c;
	int i;

	/* scan options without argument and not depending of -d */
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
			set_state(&access_set.isset, negative, c, 0);
			modify = 1;
			break;
		case 'E':
			set_state(&exec_set.isset, negative, c, 0);
			modify = 1;
			break;
		case 'M':
			set_state(&mmap_set.isset, negative, c, 0);
			modify = 1;
			break;
		case 'T':
			set_state(&transmute_flag, negative, c, 0);
			modify = 1;
			break;
		case 't':
			break;
		case 'd':
			set_state(&delete_flag, positive, c, 0);
			fprintf(stderr, "remove: option -d is obsolete!\n");
			break;
		case 'D':
			set_state(&delete_flag, negative, c, 0);
			break;
		case 'L':
			set_state(&follow_flag, positive, c, 0);
			break;
		case 'r':
			set_state(&recursive_flag, positive, c, 0);
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

	/* scan options with optional argument and -t */
	svalue = delete_flag == positive ? negative : positive;
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
		case 't':
			set_state(&transmute_flag, svalue, c, 0);
			modify = 1;
		default:
			continue;
		}

		/* greedy on optional arguments */
		if (optarg == NULL && argv[optind] != NULL
		    && argv[optind][0] != '-') {
			optarg = argv[optind++];
		}
		if (optarg == NULL) {
			if (delete_flag != positive) {
				fprintf(stderr, "%s: require a label on set.\n",
					option_by_char(c)->name);
				exit(1);
			}
		} else if (delete_flag == positive) {
			fprintf(stderr, "%s: require no label on delete.\n",
				option_by_char(c)->name);
			exit(1);
		} else if (strnlen(optarg, SMACK_LABEL_LEN + 1) ==
			   SMACK_LABEL_LEN + 1) {
			fprintf(stderr, "%s: \"%s\" exceeds %d characters.\n",
				option_by_char(c)->name, optarg,
				SMACK_LABEL_LEN);
			exit(1);
		} else if (smack_label_length(optarg) < 0) {
			fprintf(stderr, "%s: invalid Smack label '%s'.\n",
				option_by_char(c)->name, optarg);
			exit(1);
		}

		set_state(&labelset->isset, svalue, c, 1);
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
	} else if (delete_flag == positive && !modify) {
		access_set.isset = negative;
		exec_set.isset = negative;
		mmap_set.isset = negative;
		transmute_flag = negative;
		modify = 1;
	}

	/* process */
	fun = modify ? modify_file : print_file;
	if (optind == argc) {
		explore(NULL, fun, 0);
	} else {
		for (i = optind; i < argc; i++) {
			fun(argv[i]);
			if (recursive_flag)
				explore(argv[i], fun, 1);
		}
	}
	exit(0);
}
