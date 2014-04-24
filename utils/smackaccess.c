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

#include <sys/smack.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>
#include <unistd.h>
#include <getopt.h>
#include "config.h"

static const char usage[] =
	"Usage: %s [options] <subject> <object> <access>\n"
	"options:\n"
	" -v --version       output version information and exit\n"
	" -h --help          output usage information and exit\n"
;

static const char short_options[] = "vh";

static struct option options[] = {
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{NULL, 0, 0, 0}
};

int main(int argc, char **argv)
{
	const char *subject;
	const char *object;
	const char *access;
	int ret;
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

	if ((argc - optind) != 3) {
		printf(usage, basename(argv[0]));
		exit(1);
	}

	subject = argv[optind];
	object = argv[optind + 1];
	access = argv[optind + 2];

	ret = smack_have_access(subject, object, access);
	if (ret < 0) {
		fprintf(stderr,"%s: input values are invalid.\n", basename(argv[0]));
		return EXIT_FAILURE;
	}

	printf("%d\n", ret);
	return EXIT_SUCCESS;
}

