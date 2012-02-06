/*
 * This file is part of libsmack.
 *
 * Copyright (C) 2011 Intel Corporation
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
 *
 * Authors:
 * Jarkko Sakkinen <jarkko.sakkinen@intel.com>
 * Brian McGillion <brian.mcgillion@intel.com>
 */

#include "common.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>

static int apply_all(void)
{
	if (is_smackfs_mounted() != 1) {
		fprintf(stderr, "ERROR: SmackFS is not mounted.\n");
		return -1;
	}

	if (clear())
		return -1;

	if (apply_rules(ACCESSES_D_PATH, 0))
		perror("apply_rules Path");

	if (apply_cipso(CIPSO_D_PATH))
		perror("apply_cipso Path");

	return 0;
}

static int status(void)
{
	int ret = is_smackfs_mounted();

	switch (ret) {
	case 1:
		printf("SmackFS is mounted.\n");
		return 0;
	case 0:
		printf("SmackFS is not mounted.\n");
		return 0;
	default:
		return -1;
	}
}

int main(int argc, char **argv)
{
	int a;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <action>\n", argv[0]);
		return 1;
	}

	if (!strcmp(argv[1], "apply")) {
		if (apply_all())
			return 1;
	} else if (!strcmp(argv[1], "clear")) {
		if (clear())
			return 1;
	} else if (!strcmp(argv[1], "status")) {
		if (status())
			return 1;
	} else {
		fprintf(stderr, "Uknown action: %s\n", argv[1]);
		return 1;
	}

	return 0;
}
