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

int main(int argc, char *argv[])
{
	static struct option options[] = {
		{"access", required_argument, 0, 'a'},
		{"exec", required_argument, 0, 'e'},
		{"mmap", required_argument, 0, 'm'},
		{"transmute", no_argument, 0, 't'},
		{NULL, 0, 0, 0}
	};

	/*  Buffers are zeroed automatically by keeping them static variables.
	 *  No separate memset is needed this way.
	 */
	static char access_buf[SMACK_LABEL_LEN + 1];
	static char exec_buf[SMACK_LABEL_LEN + 1];
	static char mmap_buf[SMACK_LABEL_LEN + 1];
	static int options_map[128];

	char *label;
	int transmute_flag = 0;
	int option_flag = 0;
	int rc;
	int c;
	int i;

	for (i = 0; options[i].name != NULL; i++)
		options_map[options[i].val] = i;

	while ((c = getopt_long(argc, argv, "a:e:m:t", options,
				NULL)) != -1) {
		if ((c == 'a' || c == 'e' || c == 'm')) {
			if (strnlen(optarg, SMACK_LABEL_LEN + 1) == (SMACK_LABEL_LEN + 1)) {
				fprintf(stderr, "%s: %s: \"%s\" exceeds %d characters.\n",
						basename(argv[0]), options[options_map[c]].name, 
						optarg,	SMACK_LABEL_LEN);
				exit(1);
			}
			if (smack_label_length(optarg) < 0) {
				fprintf(stderr, "%s: %s: \"%s\" is an invalid Smack label.\n",
					basename(argv[0]), options[options_map[c]].name, optarg);
				exit(1);
			}
		}

		switch (c) {
			case 'a':
				strncpy(access_buf, optarg, SMACK_LABEL_LEN + 1);
				break;
			case 'e':
				strncpy(exec_buf, optarg, SMACK_LABEL_LEN + 1);
				break;
			case 'm':
				strncpy(mmap_buf, optarg, SMACK_LABEL_LEN + 1);
				break;
			case 't':
				transmute_flag = 1;
				break;
			default:
				printf(usage, basename(argv[0]));
				exit(1);
		}

		option_flag = 1;
	}

	/* setting labels */
	if (option_flag) {
		for (i = optind; i < argc; i++) {
			if (strlen(access_buf) > 0) {
				rc = smack_set_label_for_path(argv[i],
							XATTR_NAME_SMACK, 0, access_buf);
				if (rc < 0)
					perror(argv[i]);
			}

			if (strlen(exec_buf) > 0) {
				rc = smack_set_label_for_path(argv[i],
							XATTR_NAME_SMACKEXEC, 0, exec_buf);
				if (rc < 0)
					perror(argv[i]);
			}

			if (strlen(mmap_buf) > 0) {
				rc = smack_set_label_for_path(argv[i],
							XATTR_NAME_SMACKMMAP, 0, mmap_buf);
				if (rc < 0)
					perror(argv[i]);
			}

			if (transmute_flag) {
				rc = smack_set_label_for_path(argv[i],
							XATTR_NAME_SMACKTRANSMUTE, 0, "TRUE");
				if (rc < 0)
					perror(argv[i]);
			}
		}
	} 

	/* listing labels */
	else {
		for (i = optind; i < argc; i++) {

			/* Print file path. */
			printf("%s", argv[i]);

			rc = (int)smack_new_label_from_path(argv[i],
						XATTR_NAME_SMACK, 0, &label);
			if (rc > 0) {
				printf(" access=\"%s\"", label);
				free(label);
			}

			rc = (int)smack_new_label_from_path(argv[i],
						XATTR_NAME_SMACKEXEC, 0, &label);
			if (rc > 0) {
				printf(" execute=\"%s\"", label);
				free(label);
			}

			rc = (int)smack_new_label_from_path(argv[i],
						XATTR_NAME_SMACKMMAP, 0, &label);
			if (rc > 0) {
				printf(" mmap=\"%s\"", label);
				free(label);
			}

			rc = (int)smack_new_label_from_path(argv[i],
						XATTR_NAME_SMACKTRANSMUTE, 0, &label);
			if (rc > 0) {
				printf(" transmute=\"%s\"", label);
				free(label);
			}

			printf("\n");
		}
	}

	exit(0);
}
