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
 */

#include "common.h"
#include <sys/smack.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

static int apply_all(void)
{
	if (!smack_smackfs_path()) {
		fprintf(stderr, "SmackFS is not mounted.\n");
		return -1;
	}

	if (clear())
		return -1;

	if (apply_rules(ACCESSES_D_PATH, 0))
		perror("apply_rules");

	if (apply_cipso(CIPSO_D_PATH))
		perror("apply_cipso");

	return 0;
}

int main(int argc, char **argv)
{
	const char *tmp = smack_smackfs_path();
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
		if (smack_smackfs_path())
			printf("SmackFS is mounted to %s.\n",
			       smack_smackfs_path());
		else
			printf("SmackFS is not mounted.\n");
		return 0;
	}

	fprintf(stderr, "Uknown action: %s\n", argv[1]);
	return 1;
}
