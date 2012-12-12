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
#include <sys/xattr.h>
#include <unistd.h>
#include <limits.h>

#define ACC_LEN 5
#define LOAD_LEN (2 * (SMACK_LABEL_LEN + 1) + ACC_LEN)

#define LEVEL_MAX 255
#define NUM_LEN 4
#define BUF_SIZE 512
#define CAT_MAX_COUNT 240
#define CAT_MAX_VALUE 63
#define CIPSO_POS(i)   (SMACK_LABEL_LEN + 1 + NUM_LEN + NUM_LEN + i * NUM_LEN)
#define CIPSO_MAX_SIZE CIPSO_POS(CAT_MAX_COUNT)
#define CIPSO_NUM_LEN_STR "%-4d"

#define ACC_R 0x01
#define ACC_W 0x02
#define ACC_X 0x04
#define ACC_A 0x08
#define ACC_T 0x10

#define KERNEL_LONG_FORMAT "%s %s %s"
#define KERNEL_SHORT_FORMAT "%-23s %-23s %5s"
#define READ_BUF_SIZE LOAD_LEN + 1
#define SELF_LABEL_FILE "/proc/self/attr/current"

extern char *smack_mnt;

typedef int (*getxattr_func)(void*, const char*, void*, size_t);
typedef int (*setxattr_func)(const void*, const char*, const void*, size_t, int);
typedef int (*removexattr_func)(void*, const char*);

struct smack_rule {
	char subject[SMACK_LABEL_LEN + 1];
	char object[SMACK_LABEL_LEN + 1];
	int access_code;
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
static inline int access_type_to_int(const char *access_type);
static inline void int_to_access_type_c(unsigned ac, char *str);
static inline void int_to_access_type_k(unsigned ac, char *str);
static inline char* get_xattr_name(enum smack_label_type type);

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
	char access_type[ACC_LEN + 1];
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
		int_to_access_type_c(rule->access_code, access_type);

		ret = fprintf(file, "%s %s %s\n",
			      rule->subject, rule->object, access_type);
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
	rule->access_code = access_type_to_int(access_type);

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
	const char *subject, *object, *access;
	int newfd;

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

		if (subject == NULL || object == NULL || access == NULL ||
		    strtok_r(NULL, " \t\n", &ptr) != NULL) {
			errno = EINVAL;
			fclose(file);
			return -1;
		}

		if (smack_accesses_add(accesses, subject, object, access)) {
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
	unsigned access_code;
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

	access_code = access_type_to_int(access_type);
	int_to_access_type_k(access_code, access_type_k);

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

struct smack_cipso *smack_cipso_new(int fd)
{
	struct smack_cipso *cipso = NULL;
	struct cipso_mapping *mapping = NULL;
	FILE *file = NULL;
	char buf[BUF_SIZE];
	char *label, *level, *cat, *ptr;
	long int val;
	int i;
	int newfd;

	newfd = dup(fd);
	if (newfd == -1)
		return NULL;

	file = fdopen(newfd, "r");
	if (file == NULL) {
		close(newfd);
		return NULL;
	}

	cipso = calloc(sizeof(struct smack_cipso ), 1);
	if (cipso == NULL) {
		fclose(file);
		return NULL;
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
	return cipso;
err_out:
	fclose(file);
	smack_cipso_free(cipso);
	free(mapping);
	return NULL;
}

const char *smack_smackfs_path(void)
{
	return smack_mnt;
}

int smack_cipso_apply(struct smack_cipso *cipso)
{
	struct cipso_mapping *m = NULL;
	char buf[CIPSO_MAX_SIZE];
	int fd;
	int i;
	char path[PATH_MAX];

	if (!smack_mnt) {
		errno = EFAULT;
		return -1; 
	}
	
	snprintf(path, sizeof path, "%s/cipso2", smack_mnt);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;

	for (m = cipso->first; m != NULL; m = m->next) {
		sprintf(buf, "%s ", m->label);
		sprintf(&buf[SMACK_LABEL_LEN + 1], CIPSO_NUM_LEN_STR, m->level);
		sprintf(&buf[SMACK_LABEL_LEN + 1 + NUM_LEN], CIPSO_NUM_LEN_STR, m->ncats);

		for (i = 0; i < m->ncats; i++)
			sprintf(&buf[CIPSO_POS(i)], CIPSO_NUM_LEN_STR, m->cats[i]);

		if (write(fd, buf, strlen(buf)) < 0) {
			close(fd);
			return -1;
		}
	}

	close(fd);
	return 0;
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
	char path[PATH_MAX];

	snprintf(path, sizeof path, "%s/revoke-subject", smack_mnt);
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;

	ret = write(fd, subject, strnlen(subject, SMACK_LABEL_LEN));
	close(fd);

	return (ret < 0) ? -1 : 0;
}

static int internal_getlabel(void* file, char** label,
		enum smack_label_type type,
		getxattr_func getfunc)
{
	char* xattr_name = get_xattr_name(type);
	char value[SMACK_LABEL_LEN + 1];
	int ret;

	ret = getfunc(file, xattr_name, value, SMACK_LABEL_LEN + 1);
	if (ret == -1) {
		if (errno == ENODATA) {
			*label = NULL;
			return 0;
		}
		return -1;
	}

	value[ret] = '\0';
	*label = calloc(ret + 1, 1);
	if (*label == NULL)
		return -1;
	strncpy(*label, value, ret);
	return 0;
}

static int internal_setlabel(void* file, const char* label,
		enum smack_label_type type,
		setxattr_func setfunc, removexattr_func removefunc)
{
	char* xattr_name = get_xattr_name(type);

	/* Check validity of labels for LABEL_TRANSMUTE */
	if (type == SMACK_LABEL_TRANSMUTE && label != NULL) {
		if (!strcmp(label, "0"))
			label = NULL;
		else if (!strcmp(label, "1"))
			label = "TRUE";
		else
			return -1;
	}

	if (label == NULL || label[0] == '\0') {
		return removefunc(file, xattr_name);
	} else {
		int len = strnlen(label, SMACK_LABEL_LEN + 1);
		if (len > SMACK_LABEL_LEN)
			return -1;
		return setfunc(file, xattr_name, label, len, 0);
	}
}

int smack_getlabel(const char *path, char** label,
		enum smack_label_type type)
{
	return internal_getlabel((void*) path, label, type,
			(getxattr_func) getxattr);
}

int smack_lgetlabel(const char *path, char** label,
		enum smack_label_type type)
{
	return internal_getlabel((void*) path, label, type,
			(getxattr_func) lgetxattr);
}

int smack_fgetlabel(int fd, char** label,
		enum smack_label_type type)
{
	return internal_getlabel((void*) fd, label, type,
			(getxattr_func) fgetxattr);
}

int smack_setlabel(const char *path, const char* label,
		enum smack_label_type type)
{
	return internal_setlabel((void*) path, label, type,
			(setxattr_func) setxattr, (removexattr_func) removexattr);
}

int smack_lsetlabel(const char *path, const char* label,
		enum smack_label_type type)
{
	return internal_setlabel((void*) path, label, type,
			(setxattr_func) lsetxattr, (removexattr_func) lremovexattr);
}

int smack_fsetlabel(int fd, const char* label,
		enum smack_label_type type)
{
	return internal_setlabel((void*) fd, label, type,
			(setxattr_func) fsetxattr, (removexattr_func) fremovexattr);
}

static int accesses_apply(struct smack_accesses *handle, int clear)
{
	char buf[LOAD_LEN + 1];
	char access_type[ACC_LEN + 1];
	struct smack_rule *rule;
	int ret;
	int fd;
	int load2 = 1;
	char path[PATH_MAX];

	if (!smack_mnt) {
		errno = EFAULT;
		return -1; 
	}
	
	snprintf(path, sizeof path, "%s/load2", smack_mnt);
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		if (errno != ENOENT)
			return -1;
		/* fallback */
	        snprintf(path, sizeof path, "%s/load", smack_mnt);
		fd = open(path, O_WRONLY);
		if (fd < 0)
			return -1;
		load2 = 0;
	}

	if (clear)
		strcpy(access_type, "-----");

	for (rule = handle->first; rule != NULL; rule = rule->next) {
		if (!clear)
			int_to_access_type_k(rule->access_code, access_type);

		if (load2)
			ret = snprintf(buf, LOAD_LEN + 1, KERNEL_LONG_FORMAT,
				       rule->subject, rule->object,
				       access_type);
		else
			ret = snprintf(buf, LOAD_LEN + 1, KERNEL_SHORT_FORMAT,
				       rule->subject, rule->object,
				       access_type);
		if (ret < 0) {
			close(fd);
			return -1;
		}

		ret = write(fd, buf, strlen(buf));
		if (ret < 0) {
			close(fd);
			return -1;
		}
	}

	close(fd);
	return 0;
}

static inline int access_type_to_int(const char *access_type)
{
	int i;
	unsigned access;

	access = 0;
	for (i = 0; i < ACC_LEN && access_type[i] != '\0'; i++)
		switch (access_type[i]) {
		case 'r':
		case 'R':
			access |= ACC_R;
			break;
		case 'w':
		case 'W':
			access |= ACC_W;
			break;
		case 'x':
		case 'X':
			access |= ACC_X;
			break;
		case 'a':
		case 'A':
			access |= ACC_A;
			break;
		case 't':
		case 'T':
			access |= ACC_T;
			break;
		default:
			break;
		}

	return access;
}

static inline void int_to_access_type_c(unsigned access, char *str)
{
	int i;
	i = 0;
	if ((access & ACC_R) != 0)
		str[i++] = 'r';
	if ((access & ACC_W) != 0)
		str[i++] = 'w';
	if ((access & ACC_X) != 0)
		str[i++] = 'x';
	if ((access & ACC_A) != 0)
		str[i++] = 'a';
	if ((access & ACC_T) != 0)
		str[i++] = 't';
	str[i] = '\0';
}

static inline void int_to_access_type_k(unsigned access, char *str)
{
	str[0] = ((access & ACC_R) != 0) ? 'r' : '-';
	str[1] = ((access & ACC_W) != 0) ? 'w' : '-';
	str[2] = ((access & ACC_X) != 0) ? 'x' : '-';
	str[3] = ((access & ACC_A) != 0) ? 'a' : '-';
	str[4] = ((access & ACC_T) != 0) ? 't' : '-';
	str[5] = '\0';
}

static inline char* get_xattr_name(enum smack_label_type type)
{
	switch (type) {
	case SMACK_LABEL_ACCESS:
		return "security.SMACK64";
	case SMACK_LABEL_EXEC:
		return "security.SMACK64EXEC";
	case SMACK_LABEL_MMAP:
		return "security.SMACK64MMAP";
	case SMACK_LABEL_TRANSMUTE:
		return "security.SMACK64TRANSMUTE";
	case SMACK_LABEL_IPIN:
		return "security.SMACK64IPIN";
	case SMACK_LABEL_IPOUT:
		return "security.SMACK64IPOUT";
	default:
		/* Should not reach this point */
		return NULL;
	}

}
