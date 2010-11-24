/*
 * This file is part of libsmack
 *
 * Copyright (C) 2010 Nokia Corporation
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
 * Jarkko Sakkinen <ext-jarkko.2.sakkinen@nokia.com>
 */

#include "smack.h"
#include <sys/types.h>
#include <attr/xattr.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <uthash.h>

#define SMACK64_LEN 23
#define SMACK_PROC_PATH "/proc/%d/attr/current"
#define LINE_BUFFER_SIZE 255

int smack_xattr_set_to_file(const char *path, const char *attr,
			    const char *smack, SmackLabelSet labels)
{
	size_t size;
	int ret;

	if (labels != NULL)
		smack = smack_label_set_to_short_name(labels, smack);

	if (smack == NULL)
		return -1;

	size = strlen(smack);
	if (size > SMACK64_LEN)
		return -1;

	ret = setxattr(path, attr, smack, size, 0);

	return ret;
}

int smack_xattr_get_from_file(const char *path, const char *attr,
			      char **smack, SmackLabelSet labels)
{
	ssize_t ret;
	char short_name[SMACK64_LEN + 2];
	const char *result;

	ret = getxattr(path, attr, short_name, SMACK64_LEN + 1);
	if (ret < 0)
		return -1;

	short_name[ret] = '\0';

	if (labels == NULL)
		result = short_name;
	else
		result = smack_label_set_to_long_name(labels, short_name);

	if (result == NULL)
		return -1;

	*smack = strdup(result);
	if (*smack == NULL)
		return -1;

	return 0;
}

int smack_xattr_get_from_proc(int pid, char **smack, SmackLabelSet labels)
{
	char buf[LINE_BUFFER_SIZE];
	FILE *file;

	snprintf(buf, LINE_BUFFER_SIZE, SMACK_PROC_PATH, pid);

	file = fopen(buf, "r");
	if (file == NULL)
		return -1;

	if (fgets(buf, LINE_BUFFER_SIZE, file) == NULL) {
		fclose(file);
		return -1;
	}

	fclose(file);
	*smack = strdup(buf);
	return *smack != NULL ? 0 : - 1;
}

