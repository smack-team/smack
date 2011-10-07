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

#include <fcntl.h>
#include <getopt.h>
#include <smack.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static struct option opts[] = {
	{"clear",  no_argument, NULL, 'c'},
	{NULL, 0, NULL, 0}
};

int main(int argc, char **argv)
{
	SmackRuleSet rules;
	int flags = 0;
	int o = 1;
	int ret;

	while ((o = getopt_long(argc, argv, "c", opts, NULL)) != -1) {
		switch (o) {
		case 'c':
			flags = SMACK_RULE_SET_APPLY_CLEAR;
			break;
		default:
			exit(EXIT_FAILURE);
		}
	}

	rules = smack_rule_set_new(STDIN_FILENO);

	if (rules == NULL) {
		perror("smack_rule_set_new");
		exit(EXIT_FAILURE);
	}

	ret = smack_rule_set_apply(rules, SMACK_RULE_SET_APPLY_CLEAR);
	if (ret < 0) {
		perror("smack_rule_set_apply");
		exit("EXIT_FAILURE");
	}

	return EXIT_SUCCESS;
}

