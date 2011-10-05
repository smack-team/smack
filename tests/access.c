
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
 * Jarkko Sakkinen <jarkko.sakkinen@intel.com>
 */

#include <smack.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define LABEL_LEN 23
#define ACC_LEN 5
#define BUF_SIZE 512
#define DELIM " \t\n"

int main(int argc, char **argv)
{
	char buf[BUF_SIZE];
	char *ptr;
	int fd;
	char *subject;
	char *object;
	char *access_type;
	int ret;

	while (fgets(buf, BUF_SIZE, stdin) != NULL) {

		subject = strtok_r(buf, DELIM, &ptr);
		object = strtok_r(NULL, DELIM, &ptr);
		access_type = strtok_r(NULL, DELIM, &ptr);

		if (subject == NULL || object == NULL || access_type == NULL ||
		    strtok_r(NULL, DELIM, &ptr) != NULL) {
			fprintf(stderr, "Invalid rule\n");
			close(fd);
			exit(EXIT_FAILURE);
		}

		fd = open("/smack/access", O_RDWR);
		if (fd < 0) {
			perror("open");
			exit(EXIT_FAILURE);
		}
		ret = smack_have_access(fd, subject, object, access_type);
		printf("%d\n", ret);
		close(fd);
	}

	return EXIT_SUCCESS;
}

