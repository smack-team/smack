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
 */

#include <fcntl.h>
#include <getopt.h>
#include <smack.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int apply_rules(void);

int main(int argc, char **argv)
{
	int ret = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <action>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if (!strcmp(argv[1], "start"))
		ret = apply_rules();
	else if (!strcmp(argv[1], "stop"))
		ret = 0;
	else if (!strcmp(argv[1], "restart"))
		ret = 0;
	else if (!strcmp(argv[1], "status"))
		ret = 0;
	else {
		fprintf(stderr, "Uknown action: %s\n", argv[1]);
		ret = -1;
	}

	return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int apply_rules(void)
{
	SmackRuleSet rules = NULL;
	int fd = 0;
	int ret = 0;

	fd = open("/etc/smack/accesses", O_RDONLY);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	rules = smack_rule_set_new(fd);
	close(fd);
	if (rules == NULL) {
		perror("smack_rule_set_new");
		return -1;
	}

	ret = smack_rule_set_apply(rules, 0);
	smack_rule_set_free(rules);
	if (ret) {
		perror("smack_rule_set_apply");
		return -1;
	}

	return 0;
}

