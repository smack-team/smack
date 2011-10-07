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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#define LABEL_LEN 23
#define LOAD_LEN (2 * (LABEL_LEN + 1) + ACC_LEN)
#define ACC_LEN 5

#define ACC_R 0x01
#define ACC_W 0x02
#define ACC_X 0x04
#define ACC_A 0x08
#define ACC_T 0x10

#define KERNEL_FORMAT "%-23s %-23s %5s"
#define READ_BUF_SIZE 512
#define SMACKFS_MNT "/smack"

struct smack_rule {
	char subject[LABEL_LEN + 1];
	char object[LABEL_LEN + 1];
	int access_code;
	struct smack_rule *next;
};

struct _SmackRuleSet {
	struct smack_rule *first;
	struct smack_rule *last;
};

inline int access_type_to_int(const char *access_type);
inline void int_to_access_type_c(unsigned ac, char *str);
inline void int_to_access_type_k(unsigned ac, char *str);

SmackRuleSet smack_rule_set_new(int fd)
{
	SmackRuleSet rules;
	FILE *file;
	char buf[READ_BUF_SIZE];
	char *ptr;
	const char *subject, *object, *access;
	int newfd;

	rules = calloc(sizeof(struct _SmackRuleSet), 1);
	if (rules == NULL)
		return NULL;

	if (fd < 0)
		return rules;

	newfd = dup(fd);
	if (newfd == -1) {
		free(rules);
		return NULL;
	}

	file = fdopen(newfd, "r");
	if (file == NULL) {
		close(newfd);
		free(rules);
		return NULL;
	}

	while (fgets(buf, READ_BUF_SIZE, file) != NULL) {
		subject = strtok_r(buf, " \t\n", &ptr);
		object = strtok_r(NULL, " \t\n", &ptr);
		access = strtok_r(NULL, " \t\n", &ptr);

		if (subject == NULL || object == NULL || access == NULL ||
		    strtok_r(NULL, " \t\n", &ptr) != NULL) {
			errno = EINVAL;
			goto err_out;
		}

		if (smack_rule_set_add(rules, subject, object, access))
			goto err_out;
	}

	if (ferror(file))
		goto err_out;

	fclose(file);
	return rules;
err_out:
	fclose(file);
	smack_rule_set_free(rules);
	return NULL;
}

void smack_rule_set_free(SmackRuleSet handle)
{
	struct smack_rule *rule = handle->first;
	struct smack_rule *next_rule = NULL;

	while (rule != NULL) {
		next_rule = rule->next;
		free(rule);
		rule = next_rule;
	}

	free(handle);
}

int smack_rule_set_save(SmackRuleSet handle, int fd)
{
	struct smack_rule *rule = handle->first;
	char access_type[ACC_LEN + 1];
	FILE *file;
	int ret;
	int newfd;

	newfd = dup(fd);
	if (newfd == -1) {
		return -1;
	}

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
			ret = -1;
			goto out;
		}

		rule = rule->next;
	}

out:
	fclose(file);
	return ret;
}

int smack_rule_set_apply(SmackRuleSet handle, int flags)
{
	char buf[LOAD_LEN + 1];
	char access_type[ACC_LEN + 1];
	struct smack_rule *rule;
	int ret;
	int fd;

	fd = open(SMACKFS_MNT, O_WRONLY);
	if (fd < 0)
		return -1;

	if (flags & SMACK_RULE_SET_APPLY_CLEAR)
		strcpy(access_type, "-----");

	for (rule = handle->first; rule != NULL; rule = rule->next) {
		if (!(flags & SMACK_RULE_SET_APPLY_CLEAR))
			int_to_access_type_k(rule->access_code, access_type);

		ret = snprintf(buf, LOAD_LEN + 1, KERNEL_FORMAT, rule->subject, rule->object, access_type);
		if (ret < 0) {
			ret = -1;
			goto out;
		}

		ret = write(fd, buf, LOAD_LEN);
		if (ret < 0) {
			ret = -1;
			goto out;
		}
	}

out:
	close(fd);
	return ret;
}

int smack_rule_set_add(SmackRuleSet handle, const char *subject,
		       const char *object, const char *access_type)
{
	struct smack_rule *rule = NULL;

	rule = calloc(sizeof(struct smack_rule), 1);
	if (rule == NULL)
		return -1;

	strncpy(rule->subject, subject, LABEL_LEN + 1);
	strncpy(rule->object, object, LABEL_LEN + 1);
	rule->access_code = access_type_to_int(access_type);

	if (handle->first == NULL) {
		handle->first = handle->last = rule;
	} else {
		handle->last->next = rule;
		handle->last = rule;
	}

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

	fd = open(SMACKFS_MNT, O_RDWR);
	if (fd < 0)
		goto err_out;

	access_code = access_type_to_int(access_type);
	int_to_access_type_k(access_code, access_type_k);

	ret = snprintf(buf, LOAD_LEN + 1, KERNEL_FORMAT, subject, object,
		       access_type_k);
	if (ret < 0)
		goto err_out;

	if (ret != LOAD_LEN) {
		errno = ERANGE;
		goto err_out;
	}

	ret = write(fd, buf, LOAD_LEN);
	if (ret < 0)
		goto err_out;

	ret = read(fd, buf, 1);
	if (ret < 0)
		goto err_out;

	close(fd);
	return buf[0] == 1;
err_out:
	close(fd);
	return -1;
}

char *smack_get_peer_label(int fd)
{
	char dummy;
	int ret;
	socklen_t length = 1;
	char *label;

	ret = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, &dummy, &length);
	if (ret < 0 && errno != ERANGE)
		return NULL;

	label = calloc(length, 1);
	if (label == NULL)
		return NULL;

	ret = getsockopt(fd, SOL_SOCKET, SO_PEERSEC, label, &length);
	if (ret < 0) {
		free(label);
		return NULL;
	}

	return label;
}

inline int access_type_to_int(const char *access_type)
{
	int i, count;
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

inline void int_to_access_type_c(unsigned access, char *str)
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

inline void int_to_access_type_k(unsigned access, char *str)
{
	str[0] = ((access & ACC_R) != 0) ? 'r' : '-';
	str[1] = ((access & ACC_W) != 0) ? 'w' : '-';
	str[2] = ((access & ACC_X) != 0) ? 'x' : '-';
	str[3] = ((access & ACC_A) != 0) ? 'a' : '-';
	str[4] = ((access & ACC_T) != 0) ? 't' : '-';
	str[5] = '\0';
}

