/*
 * This file is part of libsmack
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
 * Brian McGillion <brian.mcgillion@intel.com>
 * Jarkko Sakkinen <jarkko.sakkinen@intel.com>
 */

#include <sys/smack.h>
#include <stdio.h>
#include <stdlib.h>
#include "common.h"

int main(int argc, char **argv)
{
	char label[LABEL_LEN + 1];
	int len;

	len = smack_get_self_label(label, LABEL_LEN);
	if (len < 0) {
		perror("smack_get_self_label");
		return EXIT_FAILURE;
	}

	label[len] = '\0';

	printf("%s", label);
	return EXIT_SUCCESS;
}
