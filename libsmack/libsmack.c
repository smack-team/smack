/*
 * This file is part of libsmack
 *
 * Copyright (C) 2010 Nokia Corporation
 * Copyright (C) 2011 Intel Corporation
 * Copyright (C) 2012 Samsung Electronics Co.
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
 * Brian McGillion <brian.mcgillion@intel.com>
 * Passion Zhao <passion.zhao@intel.com>
 * Rafal Krypa <r.krypa@samsung.com>
 */

#include "sys/smack.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <attr/xattr.h>

#define ACC_LEN 5
#define LOAD_LEN (2 * (SMACK_LABEL_LEN + 1) + 2 * ACC_LEN + 1)

#define LEVEL_MAX 255
#define NUM_LEN 4
#define BUF_SIZE 512
#define CAT_MAX_COUNT 240
#define CAT_MAX_VALUE 63
#define CIPSO_POS(i)   (SMACK_LABEL_LEN + 1 + NUM_LEN + NUM_LEN + i * NUM_LEN)
#define CIPSO_MAX_SIZE CIPSO_POS(CAT_MAX_COUNT)
#define CIPSO_NUM_LEN_STR "%-4d"

#define KERNEL_LONG_FORMAT "%s %s %s"
#define KERNEL_SHORT_FORMAT "%-23s %-23s %5s"
#define KERNEL_MODIFY_FORMAT "%s %s %s %s"
#define READ_BUF_SIZE LOAD_LEN + 1
#define SELF_LABEL_FILE "/proc/self/attr/current"

extern char *smack_mnt;

struct smack_rule {
	char subject[SMACK_LABEL_LEN + 1];
	char object[SMACK_LABEL_LEN + 1];
	int is_modify;
	char access_set[ACC_LEN + 1];
	char access_add[ACC_LEN + 1];
	char access_del[ACC_LEN + 1];
	struct smack_rule *next;
};

struct smack_accesses {
	struct smack_rule *first;
	struct smack_rule *last;
};

struct cipso_mapping {
	char label[SMACK_LABEL_LEN + 1];
	int cats[CAT_MAX_VALUE];
	int ncats;
	int level;
	struct cipso_mapping *next;
};

struct smack_cipso {
	struct cipso_mapping *first;
	struct cipso_mapping *last;
};

static int accesses_apply(struct smack_accesses *handle, int clear);
static inline void parse_access_type(const char *in, char out[ACC_LEN + 1]);

int smack_accesses_new(struct smack_accesses **accesses)
{
	struct smack_accesses *result;

	result = calloc(sizeof(struct smack_accesses), 1);
	if (result == NULL)
		return -1;

	*accesses = result;
	return 0;
}

void smack_accesses_free(struct smack_accesses *handle)
{
	if (handle == NULL)
		return;

	struct smack_rule *rule = handle->first;
	struct smack_rule *next_rule = NULL;

	while (rule != NULL) {
		next_rule = rule->next;
		free(rule);
		rule = next_rule;
	}

	free(handle);
}

int smack_accesses_save(struct smack_accesses *handle, int fd)
{
	struct smack_rule *rule = handle->first;
	FILE *file;
	int ret;
	int newfd;

	newfd = dup(fd);
	if (newfd == -1)
		return -1;

	file = fdopen(newfd, "w");
	if (file == NULL) {
		close(newfd);
		return -1;
	}

	while (rule) {
		if (rule->is_modify) {
			ret = fprintf(file, "%s %s %s %s\n",
				      rule->subject, rule->object,
				      rule->access_add, rule->access_del);
		} else {
			ret = fprintf(file, "%s %s %s\n",
				      rule->subject, rule->object,
				      rule->access_set);
		}

		if (ret < 0) {
			fclose(file);
			return -1;
		}

		rule = rule->next;
	}

	fclose(file);
	return 0;
}

int smack_accesses_apply(struct smack_accesses *handle)
{
	return accesses_apply(handle, 0);
}

int smack_accesses_clear(struct smack_accesses *handle)
{
	return accesses_apply(handle, 1);
}

int smack_accesses_add(struct smack_accesses *handle, const char *subject,
		       const char *object, const char *access_type)
{
	struct smack_rule *rule = NULL;

	rule = calloc(sizeof(struct smack_rule), 1);
	if (rule == NULL)
		return -1;

	strncpy(rule->subject, subject, SMACK_LABEL_LEN + 1);
	strncpy(rule->object, object, SMACK_LABEL_LEN + 1);
	parse_access_type(access_type, rule->access_set);

	if (handle->first == NULL) {
		handle->first = handle->last = rule;
	} else {
		handle->last->next = rule;
		handle->last = rule;
	}

	return 0;
}

int smack_accesses_add_modify(struct smack_accesses *handle, const char *subject,
		       const char *object, const char *access_add, const char *access_del)
{
	struct smack_rule *rule = NULL;

	rule = calloc(sizeof(struct smack_rule), 1);
	if (rule == NULL)
		return -1;

	strncpy(rule->subject, subject, SMACK_LABEL_LEN + 1);
	strncpy(rule->object, object, SMACK_LABEL_LEN + 1);
	parse_access_type(access_add, rule->access_add);
	parse_access_type(access_del, rule->access_del);
	rule->is_modify = 1;

	if (handle->first == NULL) {
		handle->first = handle->last = rule;
	} else {
		handle->last->next = rule;
		handle->last = rule;
	}

	return 0;
}

int smack_accesses_add_from_file(struct smack_accesses *accesses, int fd)
{
	FILE *file = NULL;
	char buf[READ_BUF_SIZE];
	char *ptr;
	const char *subject, *object, *access, *access2;
	int newfd;
	int ret;

	newfd = dup(fd);
	if (newfd == -1)
		return -1;

	file = fdopen(newfd, "r");
	if (file == NULL) {
		close(newfd);
		return -1;
	}

	while (fgets(buf, READ_BUF_SIZE, file) != NULL) {
		if (strcmp(buf, "\n") == 0)
			continue;
		subject = strtok_r(buf, " \t\n", &ptr);
		object = strtok_r(NULL, " \t\n", &ptr);
		access = strtok_r(NULL, " \t\n", &ptr);
		access2 = strtok_r(NULL, " \t\n", &ptr);

		if (subject == NULL || object == NULL || access == NULL ||
		    strtok_r(NULL, " \t\n", &ptr) != NULL) {
			errno = EINVAL;
			fclose(file);
			return -1;
		}

		if (access2 == NULL)
			ret = smack_accesses_add(accesses, subject, object, access);
		else
			ret = smack_accesses_add_modify(accesses, subject, object, access, access2);

		if (ret) {
			fclose(file);
			return -1;
		}
	}

	if (ferror(file)) {
		fclose(file);
		return -1;
	}

	fclose(file);
	return 0;
}

int smack_have_access(const char *subject, const char *object,
		      const char *access_type)
{
	char buf[LOAD_LEN + 1];
	char access_type_k[ACC_LEN + 1];
	int ret;
	int fd;
	int access2 = 1;
	char path[PATH_MAX];

	if (!smack_mnt) {
		errno = EFAULT;
		return -1; 
	}
	
	snprintf(path, sizeof path, "%s/access2", smack_mnt);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		if (errno != ENOENT)
			return -1;
		
	        snprintf(path, sizeof path, "%s/access", smack_mnt);
		fd = open(path, O_RDWR);
		if (fd < 0)
			return -1;
		access2 = 0;
	}

	parse_access_type(access_type, access_type_k);

	if (access2)
		ret = snprintf(buf, LOAD_LEN + 1, KERNEL_LONG_FORMAT,
			       subject, object, access_type_k);
	else
		ret = snprintf(buf, LOAD_LEN + 1, KERNEL_SHORT_FORMAT,
			       subject, object, access_type_k);

	if (ret < 0) {
		close(fd);
		return -1;
	}

	ret = write(fd, buf, strlen(buf));
	if (ret < 0) {
		close(fd);
		return -1;
	}

	ret = read(fd, buf, 1);
	close(fd);
	if (ret < 0)
		return -1;

	return buf[0] == '1';
}

int smack_cipso_new(struct smack_cipso **cipso)
{
	struct smack_cipso *result;

	result = calloc(sizeof(struct smack_cipso), 1);
	if (result == NULL)
		return -1;

	*cipso = result;
	return 0;
}

void smack_cipso_free(struct smack_cipso *cipso)
{
	if (cipso == NULL)
		return;

	struct cipso_mapping *mapping = cipso->first;
	struct cipso_mapping *next_mapping = NULL;

	while (mapping != NULL) {
		next_mapping = mapping->next;
		free(mapping);
		mapping = next_mapping;
	}
}

int smack_cipso_apply(struct smack_cipso *cipso)
{
	struct cipso_mapping *m = NULL;
	char buf[CIPSO_MAX_SIZE];
	int fd;
	int i;
	char path[PATH_MAX];
	int offset=0;

	if (!smack_mnt) {
		errno = EFAULT;
		return -1;
	}

	snprintf(path, sizeof path, "%s/cipso2", smack_mnt);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;

	memset(buf,0,CIPSO_MAX_SIZE);
	for (m = cipso->first; m != NULL; m = m->next) {
		snprintf(buf, SMACK_LABEL_LEN + 1, "%s", m->label);
		offset += strlen(buf) + 1;

		sprintf(&buf[offset], CIPSO_NUM_LEN_STR, m->level);
		offset += NUM_LEN;

		sprintf(&buf[offset], CIPSO_NUM_LEN_STR, m->ncats);
		offset += NUM_LEN;

		for (i = 0; i < m->ncats; i++){
			sprintf(&buf[offset], CIPSO_NUM_LEN_STR, m->cats[i]);
			offset += NUM_LEN;
		}

		if (write(fd, buf, offset) < 0) {
			close(fd);
			return -1;
		}
	}

	close(fd);
	return 0;
}

int smack_cipso_add_from_file(struct smack_cipso *cipso, int fd)
{
	struct cipso_mapping *mapping = NULL;
	FILE *file = NULL;
	char buf[BUF_SIZE];
	char *label, *level, *cat, *ptr;
	long int val;
	int i;
	int newfd;

	newfd = dup(fd);
	if (newfd == -1)
		return -1;

	file = fdopen(newfd, "r");
	if (file == NULL) {
		close(newfd);
		return -1;
	}

	while (fgets(buf, BUF_SIZE, file) != NULL) {
		mapping = calloc(sizeof(struct cipso_mapping), 1);
		if (mapping == NULL)
			goto err_out;

		label = strtok_r(buf, " \t\n", &ptr);
		level = strtok_r(NULL, " \t\n", &ptr);
		cat = strtok_r(NULL, " \t\n", &ptr);
		if (label == NULL || cat == NULL || level == NULL ||
		    strlen(label) > SMACK_LABEL_LEN) {
			errno = EINVAL;
			goto err_out;
		}

		strcpy(mapping->label, label);

		errno = 0;
		val = strtol(level, NULL, 10);
		if (errno)
			goto err_out;

		if (val < 0 || val > LEVEL_MAX) {
			errno = ERANGE;
			goto err_out;
		}

		mapping->level = val;

		for (i = 0; i < CAT_MAX_COUNT && cat != NULL; i++) {
			errno = 0;
			val = strtol(cat, NULL, 10);
			if (errno)
				goto err_out;

			if (val < 0 || val > CAT_MAX_VALUE) {
				errno = ERANGE;
				goto err_out;
			}

			mapping->cats[i] = val;

			cat = strtok_r(NULL, " \t\n", &ptr);
		}

		mapping->ncats = i;

		if (cipso->first == NULL) {
			cipso->first = cipso->last = mapping;
		} else {
			cipso->last->next = mapping;
			cipso->last = mapping;
		}
	}

	if (ferror(file))
		goto err_out;

	fclose(file);
	return 0;
err_out:
	fclose(file);
	free(mapping);
	return -1;
}

const char *smack_smackfs_path(void)
{
	return smack_mnt;
}

int smack_new_label_from_self(char **label)
{
	char *result;
	int fd;
	int ret;

	result = calloc(SMACK_LABEL_LEN + 1, 1);
	if (result == NULL)
		return -1;

	fd = open(SELF_LABEL_FILE, O_RDONLY);
	if (fd < 0) {
		free(result);
		return -1;
	}

	ret = read(fd, result, SMACK_LABEL_LEN);
	close(fd);
	if (ret < 0) {
		free(result);
		return -1;
	}

	*label = result;
	return 0;
}

int smack_new_label_from_socket(int fd, char **label)
{
	char dummy;
	int ret;
	socklen_t length = 1;
	char *result;

	ret = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, &dummy, &length);
	if (ret < 0 && errno != ERANGE)
		return -1;

	result = calloc(length + 1, 1);
	if (result == NULL)
		return -1;

	ret = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, result, &length);
	if (ret < 0) {
		free(result);
		return -1;
	}

	*label = result;
	return 0;
}

int smack_new_label_from_path(const char *path, const char *xattr, int follow,
			      const char **label)
{
	char *result;
	ssize_t ret = 0;

	ret = follow ?
		getxattr(path, xattr, NULL, 0) :
		lgetxattr(path, xattr, NULL, 0);
	if (ret < 0 && errno != ERANGE)
		return -1;

	result = calloc(ret + 1, 1);
	if (result == NULL)
		return -1;

	ret = follow ?
		getxattr(path, xattr, result, ret) :
		lgetxattr(path, xattr, result, ret);
	if (ret < 0) {
		free(result);
		return -1;
	}

	*label = result;
	return 0;
}


int smack_set_label_for_self(const char *label)
{
	int len;
	int fd;
	int ret;

	len = strnlen(label, SMACK_LABEL_LEN + 1);
	if (len > SMACK_LABEL_LEN)
		return -1;

	fd = open(SELF_LABEL_FILE, O_WRONLY);
	if (fd < 0)
		return -1;

	ret = write(fd, label, len);
	close(fd);

	return (ret < 0) ? -1 : 0;
}

int smack_revoke_subject(const char *subject)
{
	int ret;
	int fd;
	int len;
	char path[PATH_MAX];

	len = strnlen(subject, SMACK_LABEL_LEN + 1);
	if (len > SMACK_LABEL_LEN)
		return -1;

	snprintf(path, sizeof path, "%s/revoke-subject", smack_mnt);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;

	ret = write(fd, subject, len);
	close(fd);

	return (ret < 0) ? -1 : 0;
}

static int accesses_apply(struct smack_accesses *handle, int clear)
{
	char buf[LOAD_LEN + 1];
	struct smack_rule *rule;
	int ret;
	int fd;
	int load_fd;
	int change_fd;
	int load2 = 1;
	char path[PATH_MAX];

	if (!smack_mnt) {
		errno = EFAULT;
		return -1; 
	}
	
	snprintf(path, sizeof path, "%s/load2", smack_mnt);
	load_fd = open(path, O_WRONLY);
	if (load_fd < 0) {
		if (errno != ENOENT)
			return -1;
		/* fallback */
	        snprintf(path, sizeof path, "%s/load", smack_mnt);
		load_fd = open(path, O_WRONLY);
		/* Try to continue if the file doesn't exist, we might not need it. */
		if (load_fd < 0 && errno != ENOENT)
			return -1;
		load2 = 0;
	}

	snprintf(path, sizeof path, "%s/change-rule", smack_mnt);
	change_fd = open(path, O_WRONLY);
	/* Try to continue if the file doesn't exist, we might not need it. */
	if (change_fd < 0 && errno != ENOENT) {
		ret = -1;
		goto err_out;
	}

	for (rule = handle->first; rule != NULL; rule = rule->next) {
		if (clear) {
			strcpy(rule->access_set, "-----");
			rule->is_modify = 0;
		}

		if (rule->is_modify) {
			fd = change_fd;
			ret = snprintf(buf, LOAD_LEN + 1, KERNEL_MODIFY_FORMAT,
						rule->subject, rule->object,
						rule->access_add, rule->access_del);
		} else {
			fd = load_fd;
			if (load2)
				ret = snprintf(buf, LOAD_LEN + 1, KERNEL_LONG_FORMAT,
					       rule->subject, rule->object,
					       rule->access_set);
			else
				ret = snprintf(buf, LOAD_LEN + 1, KERNEL_SHORT_FORMAT,
					       rule->subject, rule->object,
					       rule->access_set);
		}

		if (ret < 0 || fd < 0) {
			ret = -1;
			goto err_out;
		}

		ret = write(fd, buf, strlen(buf));
		if (ret < 0) {
			ret = -1;
			goto err_out;
		}
	}
	ret = 0;

err_out:
	if (load_fd >= 0)
		close(load_fd);
	if (change_fd >= 0)
		close(change_fd);
	return ret;
}

static inline void parse_access_type(const char *in, char out[ACC_LEN + 1])
{
	int i;

	for (i = 0; i < ACC_LEN; ++i)
		out[i] = '-';
	out[ACC_LEN] = '\0';

	for (i = 0; in[i] != '\0'; i++)
		switch (in[i]) {
		case 'r':
		case 'R':
			out[0] = 'r';
			break;
		case 'w':
		case 'W':
			out[1] = 'w';
			break;
		case 'x':
		case 'X':
			out[2] = 'x';
			break;
		case 'a':
		case 'A':
			out[3] = 'a';
			break;
		case 't':
		case 'T':
			out[4] = 't';
			break;
		default:
			break;
		}
}


