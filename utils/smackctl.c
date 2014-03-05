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

static void usage(const char *bin)
{
	printf("Usage: %s [action]\n", bin);
	printf("actions:\n");
	printf(" [apply] apply all the rules found in the configuration directory's\n");
	printf(" [clear] remove all system rules from the kernel\n");
	printf(" [status] show the status of the Smack system, specifically if "
	       "/smack is mounted\n");
	exit(1);
}

static int apply_all(void)
{
	if (!smack_smackfs_path()) {
		fprintf(stderr, "SmackFS is not mounted.\n");
		return -1;
	}

	if (clear())
		return -1;

	if (apply_rules(ACCESSES_D_PATH, 0))
		return -1;

	if (apply_cipso(CIPSO_D_PATH))
		return -1;

	return 0;
}

int main(int argc, char **argv)
{
	const char *tmp = smack_smackfs_path();
	if (argc < 2) {
		usage(argv[0]);
	}

	if (!strcmp(argv[1], "apply")) {
		if (apply_all())
			exit(1);
	} else if (!strcmp(argv[1], "clear")) {
		if (clear())
			exit(1);
	} else if (!strcmp(argv[1], "status")) {
		if (tmp)
			printf("SmackFS is mounted to %s.\n", tmp);
		else
			printf("SmackFS is not mounted.\n");
		exit(0);
	} else {
		usage(argv[0]);
	}

	exit(0);
}
