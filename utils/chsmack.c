/*
 * chsmack - Set smack attributes on files
 *
 * Copyright (C) 2011 Nokia Corporation.
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation, version 2.
 *
 *	This program is distributed in the hope that it will be useful, but
 *	WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 *	General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public
 *	License along with this program; if not, write to the Free Software
 *	Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 *	02110-1301 USA
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/smack.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

int main(int argc, char *argv[])
{
	static struct option long_options[] = {
		{"access", required_argument, 0, 'a'},
		{"exec", required_argument, 0, 'e'},
		{"mmap", required_argument, 0, 'm'},
		{"transmute", no_argument, 0, 't'},
		{0, 0, 0, 0}
	};

	/*  Buffers are zeroed automatically by keeping them static variables.
	 *  No separate memset is needed this way.
	 */
	static char access_buf[SMACK_LABEL_LEN + 1];
	static char exec_buf[SMACK_LABEL_LEN + 1];
	static char mmap_buf[SMACK_LABEL_LEN + 1];

	int transmute_flag = 0;
	int option_flag = 0;
	int option_index;
	int rc;
	int c;
	int i;

	while ((c = getopt_long(argc, argv, "a:e:m:t", long_options,
				&option_index)) != -1) {
		if ((c == 'a' || c == 'e' || c == 'm')
		    && strnlen(optarg, SMACK_LABEL_LEN + 1)
		       == (SMACK_LABEL_LEN + 1)) {
			fprintf(stderr, "%s label \"%s\" "
					"exceeds %d characters.\n",
				long_options[option_index].name, optarg,
				SMACK_LABEL_LEN);
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
				printf("Usage: %s [options] <path>\n", argv[0]);
				printf("options:\n");
				printf(" [--access|-a] set security.SMACK64\n");
				printf(" [--exec|-e] set security.SMACK64EXEC\n");
				printf(" [--mmap|-m] set security.SMACK64MMAP\n");
				printf(" [--transmute|-t] set security.SMACK64TRANSMUTE\n");
				exit(1);
		}

		option_flag = 1;
	}

	for (i = optind; i < argc; i++) {
		if (option_flag) {
			if (strlen(access_buf) > 0) {
				rc = lsetxattr(argv[i], "security.SMACK64",
					       access_buf, strlen(access_buf) + 1, 0);
				if (rc < 0)
					perror(argv[i]);
			}

			if (strlen(exec_buf) > 0) {
				rc = lsetxattr(argv[i], "security.SMACK64EXEC",
					       exec_buf, strlen(exec_buf) + 1, 0);
				if (rc < 0)
					perror(argv[i]);
			}

			if (strlen(mmap_buf) > 0) {
				rc = lsetxattr(argv[i], "security.SMACK64MMAP",
					       mmap_buf, strlen(mmap_buf) + 1, 0);
				if (rc < 0)
					perror(argv[i]);
			}

			if (transmute_flag) {
				rc = lsetxattr(argv[i], "security.SMACK64TRANSMUTE",
					       "TRUE", 4, 0);
				if (rc < 0)
					perror(argv[i]);
			}
		} else {
			/* Print file path. */
			printf("%s", argv[i]);

			rc = lgetxattr(argv[i], "security.SMACK64", access_buf,
				       SMACK_LABEL_LEN + 1);
			if (rc > 0) {
				access_buf[rc] = '\0';
				printf(" access=\"%s\"", access_buf);
			}

			rc = lgetxattr(argv[i], "security.SMACK64EXEC", access_buf,
				       SMACK_LABEL_LEN + 1);
			if (rc > 0) {
				access_buf[rc] = '\0';
				printf(" execute=\"%s\"", access_buf);

			}
			rc = lgetxattr(argv[i], "security.SMACK64MMAP", access_buf,
				       SMACK_LABEL_LEN + 1);
			if (rc > 0) {
				access_buf[rc] = '\0';
				printf(" mmap=\"%s\"", access_buf);
			}

			rc = lgetxattr(argv[i], "security.SMACK64TRANSMUTE",
				       access_buf, SMACK_LABEL_LEN + 1);
			if (rc > 0) {
				access_buf[rc] = '\0';
				printf(" transmute=\"%s\"", access_buf);
			}

			printf("\n");
		}
	}

	exit(0);
}
