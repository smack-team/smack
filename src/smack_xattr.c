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

#define SMACK64 "security.SMACK64"
#define SMACK64EXEC "security.SMACK64EXEC"
#define SMACK64_LEN 23
#define SMACK_PROC_PATH "/proc/%d/attr/current"
#define LINE_BUFFER_SIZE 255

int smack_set_smack_to_file(const char *path, const char *smack, int flags)
{
	size_t size;
	int ret;

	size = strlen(smack);
	if (size > SMACK64_LEN)
		return -1;

	if ((flags & SMACK_XATTR_SYMLINK) == 0)
		ret = setxattr(path, SMACK64, smack, size, 0);
	else
		ret = lsetxattr(path, SMACK64, smack, size, 0);

	return ret;
}

int smack_get_smack_from_file(const char *path, char **smack, int flags)
{
	ssize_t ret;
	char *buf;

	if ((flags & SMACK_XATTR_SYMLINK) == 0)
		ret = getxattr(path, SMACK64, NULL, 0);
	else
		ret = lgetxattr(path, SMACK64, NULL, 0);

	if (ret < 0)
		return -1;

	buf = malloc(ret + 1);

	if ((flags & SMACK_XATTR_SYMLINK) == 0)
		ret = getxattr(path, SMACK64, buf, ret);
	else
		ret = lgetxattr(path, SMACK64, buf, ret);

	if (ret < 0) {
		free(buf);
		return -1;
	}

	buf[ret] = '\0';
	*smack = buf;
	return 0;
}

int smack_get_smack_from_proc(int pid, char **smack)
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

int smack_set_smackexec_to_file(const char *path, const char *smack, int flags)
{
	size_t size;
	int ret;

	size = strlen(smack);
	if (size > SMACK64_LEN)
		return -1;

	if ((flags & SMACK_XATTR_SYMLINK) == 0)
		ret = setxattr(path, SMACK64EXEC, smack, size, 0);
	else
		ret = lsetxattr(path, SMACK64EXEC, smack, size, 0);

	return ret;
}

int smack_get_smackexec_from_file(const char *path, char **smack, int flags)
{
	ssize_t ret;
	char *buf;

	if ((flags & SMACK_XATTR_SYMLINK) == 0)
		ret = getxattr(path, SMACK64EXEC, NULL, 0);
	else
		ret = lgetxattr(path, SMACK64EXEC, NULL, 0);

	if (ret < 0)
		return -1;

	buf = malloc(ret + 1);

	if ((flags & SMACK_XATTR_SYMLINK) == 0)
		ret = getxattr(path, SMACK64EXEC, buf, ret);
	else
		ret = lgetxattr(path, SMACK64EXEC, buf, ret);

	if (ret < 0) {
		free(buf);
		return -1;
	}

	buf[ret] = '\0';
	*smack = buf;
	return 0;
}

