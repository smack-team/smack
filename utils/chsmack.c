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

static const char usage[] =
	"Usage: %s [options] <path>\n"
	"options:\n"  
	" -a --access        set/remove "XATTR_NAME_SMACK"\n"  
	" -e --exec          set/remove "XATTR_NAME_SMACKEXEC"\n"  
	" -m --mmap          set/remove "XATTR_NAME_SMACKMMAP"\n"  
	" -t --transmute     set/remove "XATTR_NAME_SMACKTRANSMUTE"\n"
	" -d --remove        tell to remove the attribute\n"
	" -L --dereference   tell to follow the symbolic links\n"
;

/*!
 * Validate a SMACK label and calculate its length.
 *
 * @param label label to verify
 * @return Returns length of the label on success and negative on failure.
 */
static ssize_t smack_label_length(const char *label)
{
	int i;

	if (!label || !*label || *label=='-')
		return -1;

	for (i = 0 ; i <= SMACK_LABEL_LEN ; i++) {
		if (label[i] == '\0')
				return (ssize_t) i;
		if (label[i] > '~' || label[i] <= ' ' || label[i] == '/' ||
		    label[i] == '"' || label[i] == '\\' || label[i] == '\'')
				return -1;
	}

	return -1;
}

/*!
  * Set the SMACK label in an extended attribute.
  *
  * @param path path of the file
  * @param xattr the extended attribute containing the SMACK label
  * @param follow whether or not to follow symbolic link
  * @param label output variable for the returned label
  * @return Returns length of the label on success and negative value
  * on failure.
  */
static int smack_set_label_for_path(const char *path,
				  const char *xattr,
				  int follow,
				  const char *label)
{
	int len;
	int ret;

	len = (int)smack_label_length(label);
	if (len < 0)
		return -2;

	ret = follow ?
		setxattr(path, xattr, label, len, 0) :
		lsetxattr(path, xattr, label, len, 0);
	return ret;
}

/*!
  * Remove the SMACK label in an extended attribute.
  *
  * @param path path of the file
  * @param xattr the extended attribute containing the SMACK label
  * @param follow whether or not to follow symbolic link
  * @return Returns 0 on success and negative on failure.
  */
static int smack_remove_label_for_path(const char *path,
				  const char *xattr,
				  int follow)
{
	return follow ? removexattr(path, xattr) : lremovexattr(path, xattr);
}

/* main */
int main(int argc, char *argv[])
{
	static const char shortoptions[] = "a::e::m::tdL";
	static struct option options[] = {
		{"access", optional_argument, 0, 'a'},
		{"exec", optional_argument, 0, 'e'},
		{"mmap", optional_argument, 0, 'm'},
		{"transmute", no_argument, 0, 't'},
		{"dereference", no_argument, 0, 'L'},
		{NULL, 0, 0, 0}
	};

	/*  Buffers are zeroed automatically by keeping them static variables.
	 *  No separate memset is needed this way.
	 */
	static int options_map[128];

	/* structure for recording options of label and their init */
	struct labelset {
		int isset; /* 0 if option not set, 1 if option set */
		const char *value; /* value of the option set if any or NULL else */
	};
	struct labelset access_set = { 0, NULL }; /* for option "access" */
	struct labelset exec_set = { 0, NULL }; /* for option "exec" */
	struct labelset mmap_set = { 0, NULL }; /* for option "mmap" */

	struct labelset *labelset;
	struct stat st;
	char *label;

	int delete_flag = 0;
	int follow_flag = 0;
	int transmute_flag = 0;
	int option_flag = 0;
	int rc;
	int c;
	int i;

	for (i = 0; options[i].name != NULL; i++)
		options_map[options[i].val] = i;

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
			case 't':
				if (transmute_flag)
					fprintf(stderr, "%s: %s: option set many times.\n",
							basename(argv[0]), options[options_map[c]].name);
				transmute_flag = 1;
				option_flag = 1;
				break;
			case 'd':
				if (delete_flag)
					fprintf(stderr, "%s: %s: option set many times.\n",
							basename(argv[0]), options[options_map[c]].name);
				delete_flag = 1;
				break;
			case 'L':
				if (follow_flag)
					fprintf(stderr, "%s: %s: option set many times.\n",
							basename(argv[0]), options[options_map[c]].name);
				follow_flag = 1;
				break;
			default:
				printf(usage, basename(argv[0]));
				exit(1);
		}
	}

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

		if (labelset->isset) {
			fprintf(stderr, "%s: %s: option set many times.\n",
				basename(argv[0]), options[options_map[c]].name);
			exit(1);
		}
		/* greedy on optional arguments */
		if (optarg == NULL && argv[optind] != NULL && argv[optind][0] != '-') {
			optarg = argv[optind++];
		}
		if (optarg == NULL) {
			if (!delete_flag) {
				fprintf(stderr, "%s: %s: requires a label when setting.\n",
					basename(argv[0]), options[options_map[c]].name);
				exit(1);
			}
		}
		else if (delete_flag) {
			fprintf(stderr, "%s: %s: requires no label when deleting.\n",
				basename(argv[0]), options[options_map[c]].name);
			exit(1);
		}
		else if (strnlen(optarg, SMACK_LABEL_LEN + 1) == SMACK_LABEL_LEN + 1) {
			fprintf(stderr, "%s: %s: \"%s\" exceeds %d characters.\n",
				basename(argv[0]), options[options_map[c]].name, optarg,
				 SMACK_LABEL_LEN);
			exit(1);
		}
		else if (smack_label_length(optarg) < 0) {
			fprintf(stderr, "%s: %s: \"%s\" is an invalid Smack label.\n",
				basename(argv[0]), options[options_map[c]].name, optarg);
			exit(1);
		}
		labelset->isset = 1;
		labelset->value = optarg;
		option_flag = 1;
	}

	/* deleting labels */
	if (delete_flag) {
		if (!option_flag) {
			access_set.isset = 1;
			exec_set.isset = 1;
			mmap_set.isset = 1;
			transmute_flag = 1;
		}
		for (i = optind; i < argc; i++) {
			if (access_set.isset) {
				rc = smack_remove_label_for_path(argv[i],
							XATTR_NAME_SMACK, follow_flag);
				if (rc < 0 && (option_flag || errno != ENODATA))
					perror(argv[i]);
			}

			if (exec_set.isset) {
				rc = smack_remove_label_for_path(argv[i],
							XATTR_NAME_SMACKEXEC, follow_flag);
				if (rc < 0 && (option_flag || errno != ENODATA))
					perror(argv[i]);
			}

			if (mmap_set.isset) {
				rc = smack_remove_label_for_path(argv[i],
							XATTR_NAME_SMACKMMAP, follow_flag);
				if (rc < 0 && (option_flag || errno != ENODATA))
					perror(argv[i]);
			}

			if (transmute_flag) {
				rc = smack_remove_label_for_path(argv[i],
							XATTR_NAME_SMACKTRANSMUTE, follow_flag);
				if (rc < 0 && (option_flag || errno != ENODATA))
					perror(argv[i]);
			}
		}
	}

	/* setting labels */
	else if (option_flag) {
		for (i = optind; i < argc; i++) {
			if (access_set.isset) {
				rc = smack_set_label_for_path(argv[i],
							XATTR_NAME_SMACK, follow_flag, access_set.value);
				if (rc < 0)
					perror(argv[i]);
			}

			if (exec_set.isset) {
				rc = smack_set_label_for_path(argv[i],
							XATTR_NAME_SMACKEXEC, follow_flag, exec_set.value);
				if (rc < 0)
					perror(argv[i]);
			}

			if (mmap_set.isset) {
				rc = smack_set_label_for_path(argv[i],
							XATTR_NAME_SMACKMMAP, follow_flag, mmap_set.value);
				if (rc < 0)
					perror(argv[i]);
			}

			if (transmute_flag) {
				rc = follow_flag ?  stat(argv[i], &st) : lstat(argv[i], &st);
				if (rc < 0)
					perror(argv[i]);
				else if (!S_ISDIR(st.st_mode)) {
					fprintf(stderr, "%s: transmute: not a directory %s\n",
						basename(argv[0]), argv[i]);
				}
				else {
					rc = smack_set_label_for_path(argv[i],
								XATTR_NAME_SMACKTRANSMUTE, follow_flag, "TRUE");
					if (rc < 0)
						perror(argv[i]);
				}
			}
		}
	}

	/* listing labels */
	else {
		for (i = optind; i < argc; i++) {

			/* Print file path. */
			printf("%s", argv[i]);

			rc = (int)smack_new_label_from_path(argv[i],
						XATTR_NAME_SMACK, follow_flag, &label);
			if (rc > 0) {
				printf(" access=\"%s\"", label);
				free(label);
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
