/*
 * This file is part of libsmack
 *
 * Copyright (C) 2010 Nokia Corporation
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
 * Brian McGillion <brian.mcgillion@intel.com>
 */

#include "smack.h"
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <uthash.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>

#define LABEL_LEN 23

#define ACC_R   0x01
#define ACC_W   0x02
#define ACC_X   0x04
#define ACC_A   0x08
#define ACC_T   0x10
#define ACC_LEN 5

#define LOAD_SIZE (2 * (LABEL_LEN + 1) + ACC_LEN + 1)

#define KERNEL_FORMAT "%-23s %-23s %5s"

#define READ_BUF_SIZE 512

struct smack_object {
	char *object;
	unsigned ac;
	char acstr[ACC_LEN + 1];
	UT_hash_handle hh;
};

struct smack_subject {
	char *subject;
	struct smack_object *objects;
	UT_hash_handle hh;
};

struct _SmackRuleSet {
	struct smack_subject *subjects;
};

static int update_rule(struct smack_subject **subjects,
		       const char *subject_str, const char *object_str,
		       unsigned ac);
inline unsigned str_to_ac(const char *str);
inline void ac_to_config_str(unsigned ac, char *str);
inline void ac_to_kernel_str(unsigned ac, char *str);

SmackRuleSet smack_rule_set_new(const char *path)
{
	SmackRuleSet rules;
	FILE *file;
	char buf[READ_BUF_SIZE];
	const char *subject, *object, *access;
	unsigned ac;
	size_t size;
	int err, ret;

	rules = calloc(1, sizeof(struct _SmackRuleSet));
	if (rules == NULL)
		return NULL;

	if (path == NULL)
		return rules;

	file = fopen(path, "r");
	if (file == NULL) {
		free(rules);
		return NULL;
	}

	ret = 0;

	while (fgets(buf, READ_BUF_SIZE, file) != NULL) {
		subject = strtok(buf, " \t\n");
		object = strtok(NULL, " \t\n");
		access = strtok(NULL, " \t\n");

		if (subject == NULL || object == NULL || access == NULL ||
		    strtok(NULL, " \t\n") != NULL) {
			ret = -1;
			break;
		}

		ac = str_to_ac(access);
		err = update_rule(&rules->subjects, subject, object,
				  ac);
		if (err != 0) {
			ret = -1;
			break;
		}
	}

	if (ret != 0 || ferror(file)) {
		smack_rule_set_free(rules);
		rules = NULL;
	}

	fclose(file);
	return rules;
}

void smack_rule_set_free(SmackRuleSet handle)
{
	struct smack_subject *s;
	struct smack_object *o;

	if (handle == NULL)
		return;

	while (handle->subjects != NULL) {
		s = handle->subjects;
		while (s->objects != NULL) {
			o = s->objects;
			HASH_DEL(s->objects, o);
			free(o->object);
			free(o);
		}
		HASH_DEL(handle->subjects, s);
		free(s->subject);
		free(s);
	}

	free(handle);
}

int smack_rule_set_save(SmackRuleSet handle, const char *path)
{
	struct smack_subject *s, *stmp;
	struct smack_object *o, *otmp;
	char astr[ACC_LEN + 1];
	FILE *file;
	int err, ret;

	ret = 0;

	file = fopen(path, "w+");
	if (!file)
		return -1;

	HASH_ITER(hh, handle->subjects, s, stmp) {
		HASH_ITER(hh, s->objects, o, otmp) {
			if (o->ac == 0)
				continue;

			ac_to_config_str(o->ac, astr);

			err = fprintf(file, "%s %s %s\n",
				      s->subject, o->object, astr);
			if (err < 0) {
				ret = -1;
				goto out;
			}
		}
	}

out:
	fclose(file);
	return ret;
}

int smack_rule_set_apply_kernel(SmackRuleSet handle, const char *path)
{
	struct smack_subject *s, *stmp;
	struct smack_object *o, *otmp;
	FILE *file;
	char str[6];
	int err = 0;

	file = fopen(path, "w");
	if (!file)
		return -1;

	HASH_ITER(hh, handle->subjects, s, stmp) {
		HASH_ITER(hh, s->objects, o, otmp) {
			ac_to_kernel_str(o->ac, str);

			err = fprintf(file, KERNEL_FORMAT "\n",
				      s->subject, o->object, str);

			if (err < 0) {
				fclose(file);
				return -1;
			}
		}
	}

	fclose(file);
	return 0;
}

int smack_rule_set_clear_kernel(SmackRuleSet handle, const char *path)
{
	struct smack_subject *s, *stmp;
	struct smack_object *o, *otmp;
	FILE *file;
	char str[6];
	int err = 0;

	file = fopen(path, "w");
	if (!file)
		return -1;

	HASH_ITER(hh, handle->subjects, s, stmp) {
		HASH_ITER(hh, s->objects, o, otmp) {
			ac_to_kernel_str(0, str);

			err = fprintf(file, "%-23s %-23s %4s\n",
				      s->subject, o->object, str);

			if (err < 0) {
				fclose(file);
				return -1;
			}
		}
	}

	fclose(file);
	return 0;
}

int smack_rule_set_add(SmackRuleSet handle, const char *subject,
		       const char *object, const char *access_str)
{
	unsigned access;
	int ret;

	access = str_to_ac(access_str);
	ret = update_rule(&handle->subjects, subject, object, access);
	return ret == 0 ? 0  : -1;
}

int smack_rule_set_have_access(SmackRuleSet handle, const char *subject,
			       const char *object, const char *access_str)
{
	struct smack_subject *s = NULL;
	struct smack_object *o = NULL;
	unsigned ac;

	ac = str_to_ac(access_str);

	HASH_FIND_STR(handle->subjects, subject, s);
	if (s == NULL)
		return 0;

	HASH_FIND_STR(s->objects, object, o);
	if (o == NULL)
		return 0;

	return ((o->ac & ac) == ac);
}

int smack_have_access(const char *path, const char *subject,
		      const char *object, const char *access_type)
{
	char buf[LOAD_SIZE];
	int fd;
	int ret;

	ret = snprintf(buf, LOAD_SIZE, KERNEL_FORMAT, subject, object, access_type);
	if (ret < 0)
		return -1;

	if (ret != (LOAD_SIZE - 1)) {
		errno = ERANGE;
		return -1;
	}

	fd = open(path, O_RDWR);
	ret = write(fd, buf, LOAD_SIZE - 1);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	ret = read(fd, buf, 1);
	if (ret < 0) {
		close(fd);
		return -1;
	}

	close(fd);
	return buf[0] == '1';
}

int smack_get_peer_label(int sock_fd, char **label)
{
	char dummy;
	int ret;
	socklen_t length = 1;
	char *value;

	ret = getsockopt(sock_fd, SOL_SOCKET, SO_PEERSEC, &dummy, &length);
	if (ret < 0 && errno != ERANGE)
		return -1;

	value = calloc(length, 1);
	if (value == NULL)
		return -1;

	ret = getsockopt(sock_fd, SOL_SOCKET, SO_PEERSEC, value, &length);
	if (ret < 0) {
		free(value);
		return -1;
	}

	*label = value;
	return 0;
}

static int update_rule(struct smack_subject **subjects,
		       const char *subject_str,
		       const char *object_str, unsigned ac)
{
	struct smack_subject *s = NULL;
	struct smack_object *o = NULL;

	if (strlen(subject_str) > LABEL_LEN &&
	    strlen(object_str) > LABEL_LEN)
		return -ERANGE;

	HASH_FIND_STR(*subjects, subject_str, s);
	if (s == NULL) {
		s = calloc(1, sizeof(struct smack_subject));
		s->subject = strdup(subject_str);
		HASH_ADD_KEYPTR(hh, *subjects, s->subject, strlen(s->subject), s);
	}

	HASH_FIND_STR(s->objects, object_str, o);
	if (o == NULL) {
		o = calloc(1, sizeof(struct smack_object));
		o->object = strdup(object_str);
		HASH_ADD_KEYPTR(hh, s->objects, o->object, strlen(o->object), o);
	}

	o->ac = ac;
	ac_to_config_str(ac, o->acstr);
	return 0;
}

inline unsigned str_to_ac(const char *str)
{
	int i, count;
	unsigned access;

	access = 0;

	count = strlen(str);
	for (i = 0; i < count; i++)
		switch (str[i]) {
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

inline void ac_to_config_str(unsigned access, char *str)
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

inline void ac_to_kernel_str(unsigned access, char *str)
{
	str[0] = ((access & ACC_R) != 0) ? 'r' : '-';
	str[1] = ((access & ACC_W) != 0) ? 'w' : '-';
	str[2] = ((access & ACC_X) != 0) ? 'x' : '-';
	str[3] = ((access & ACC_A) != 0) ? 'a' : '-';
	str[3] = ((access & ACC_T) != 0) ? 't' : '-';
	str[4] = '\0';
}

