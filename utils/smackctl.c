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
#include <sys/smack.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include "config.h"

static const char usage[] = 
	"Usage: %s [option] [action]\n"
	"options:\n"
	" -v --version       output version information and exit\n"
	" -h --help          output usage information and exit\n"
	"actions:\n"
	" apply   apply all the rules found in the configuration directory's\n"
	" clear   remove all system rules from the kernel\n"
	" status  show the status of the Smack system, specifically if "
	       "smackfs is mounted\n"
;

static const char short_options[] = "vh";

static struct option options[] = {
	{"version", no_argument, NULL, 'v'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0}
};

int main(int argc, char **argv)
{
	int c;

	for ( ; ; ) {
		c = getopt_long(argc, argv, short_options, options, NULL);

		if (c == -1)
			break;

		switch (c) {
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

	if ((argc - optind) != 1) {
		printf(usage, basename(argv[0]));
		exit(1);
	}

	if (!strcmp(argv[1], "apply")) {
		if (smack_load_policy())
			exit(1);
	} else if (!strcmp(argv[1], "clear")) {
		if (clear())
			exit(1);
	} else if (!strcmp(argv[1], "status")) {
		if (smack_smackfs_path())
			printf("SmackFS is mounted to %s\n",
			       smack_smackfs_path());
		else
			printf("SmackFS is not mounted.\n");
		exit(0);
	} else {
		fprintf(stderr, "Uknown action: %s\n", argv[1]);
		fprintf(stderr, usage, argv[0]);
		exit(1);
	}

	exit(0);
	return 0;
}
