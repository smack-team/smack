/*
 * This file is part of libsmack
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
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/smack.h>

int main(int argc, char **argv)
{
	if (!smack_smackfs_path()) {
		fprintf(stderr, "SmackFS is not mounted.\n");
		exit(1);
	}

	if (argc > 2) {
		fprintf(stderr, "Usage: %s <path>\n", argv[0]);
		exit(1);
	}

	if (argc == 1) {
		if (apply_cipso(NULL))
			exit(1);
	} else {
		if (apply_cipso(argv[1]))
			exit(1);
	}

	exit(0);
}
