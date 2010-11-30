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
#include "smack_internal.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>

#define SMACK_DIR_PATH "/etc/smack"

int smack_create_default_config_files()
{
	int ret, fd;

	ret = access(SMACK_DIR_PATH, F_OK);
	if (ret != 0 && errno != ENOENT)
		return -1;
	if (ret != 0) {
		mkdir(SMACK_DIR_PATH,  S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	}

	ret = access(SMACK_ACCESSES_PATH, F_OK);
	if (ret != 0 && errno != ENOENT)
		return -1;
	if (ret != 0) {
		fd = creat(SMACK_ACCESSES_PATH, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		if (fd == -1)
			return -1;
		close(fd);
	}

	ret = access(SMACK_LABELS_PATH, F_OK);
	if (ret != 0 && errno != ENOENT)
		return -1;
	if (ret != 0) {
		fd = creat(SMACK_LABELS_PATH, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
		if (fd == -1)
			return -1;
		close(fd);
	}

	return 0;
}
