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

struct smack_user {
	char *user;
	char label[SMACK64_LEN + 1];
	UT_hash_handle hh;
};

struct smack_users {
	struct smack_user *users;
};

static int update_user(struct smack_user **users,
		       const char *user, const char *label);
static void destroy_users(struct smack_user **users);

smack_users_t smack_create_users()
{
	struct smack_users *result =
		calloc(1, sizeof(struct smack_users));
	return result;
}

void smack_destroy_users(smack_users_t handle)
{
	destroy_users(&handle->users);
	free(handle);
}

int smack_read_users_from_file(smack_users_t handle, const char *path)
{
	FILE *file;
	char *buf = NULL;
	size_t size;
	const char *user, *label;
	struct smack_user *users = NULL;
	int ret = 0;

	file = fopen(path, "r");
	if (file == NULL)
		return -1;

	while (ret == 0 && getline(&buf, &size, file) != -1) {
		user = strtok(buf, " \n");
		label = strtok(NULL, " \n");

		if (user == NULL || label == NULL ||
		    strtok(NULL, " \n") != NULL)
			ret = -1;
		else
			ret = update_user(&users, user, label);

		free(buf);
		buf = NULL;
	}

	if (ferror(file))
		ret = -1;

	if (ret == 0) {
		destroy_users(&handle->users);
		handle->users = users;
	} else {
		destroy_users(&users);
	}

	free(buf);
	fclose(file);
	return 0;
}

int smack_write_users_to_file(smack_users_t handle, const char *path)
{
	struct smack_user *u, *tmp;
	FILE *file;
	int err;

	file = fopen(path, "w+");
	if (!file)
		return -1;

	HASH_ITER(hh, handle->users, u, tmp) {
		err = fprintf(file, "%s %s\n",
			      u->user, u->label);
		if (err < 0) {
			fclose(file);
			return errno;
		}
	}

	fclose(file);
	return 0;
}

const char *smack_get_user_label(smack_users_t handle, const char *user)
{
	struct smack_user *u;

	HASH_FIND_STR(handle->users, user, u);

	if (u == NULL)
		return;

	return u->label;
}

static int update_user(struct smack_user **users,
		       const char *user, const char *label)
{
	struct smack_user *u = NULL;

	if (strlen(label) > SMACK64_LEN)
		return -ERANGE;

	HASH_FIND_STR(*users, user, u);
	if (u == NULL) {
		u = calloc(1, sizeof(struct smack_user));
		u->user = strdup(user);
		HASH_ADD_KEYPTR( hh, *users, u->user, strlen(u->user), u);
	}

	strcpy(u->label, label);
	return 0;
}

static void destroy_users(struct smack_user **users)
{
	struct smack_user *u, *tmp;

	HASH_ITER(hh, *users, u, tmp) {
		HASH_DEL(*users, u);
		free(u->user);
		free(u);
	}
}

