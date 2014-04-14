/*
 * This file is part of libsmack
 *
 * Copyright (C) 2011, 2013 Intel Corporation
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
#include <stdlib.h>
#include <stdio.h>
#include <sys/smack.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include "config.h"

static const char usage[] =
	"Usage: %s [options] <subject> <object> <access>\n"
	"options:\n"
	" -v --version       output version information and exit\n"
	" -h --help          output usage information and exit\n"
	" -c --clear         clear access rules\n"
;

static const char short_options[] = "vhc";

static struct option options[] = {
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{"clear", no_argument, 0, 'c'},
	{NULL, 0, 0, 0}
};

int main(int argc, char **argv)
{
	int clear = 0;
	int c;

	for ( ; ; ) {
		c = getopt_long(argc, argv, short_options, options, NULL);

		if (c == -1)
			break;

		switch (c) {
		case 'c':
			clear = 1;
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

	if (!smack_smackfs_path()) {
		fprintf(stderr, "SmackFS is not mounted.\n");
		exit(1);
	}

	if ((argc - optind) > 1) {
		printf(usage, basename(argv[0]));
		exit(1);
	}

	if (optind == argc) {
		if (apply_rules(NULL, clear))
			exit(1);
	} else {
		if (apply_rules(argv[optind], clear))
			exit(1);
	}

	exit(0);
}
