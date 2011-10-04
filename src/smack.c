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
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

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

struct smack_rule {
	char subject[LABEL_LEN + 1];
	char object[LABEL_LEN + 1];
	unsigned access_code;
};

struct _SmackRuleSet {
	GList *rules;
};

inline unsigned str_to_ac(const char *str);
inline void ac_to_config_str(unsigned ac, char *str);
inline void ac_to_kernel_str(unsigned ac, char *str);

SmackRuleSet smack_rule_set_new(int fd)
{
	SmackRuleSet rules;
	FILE *file;
	char buf[READ_BUF_SIZE];
	const char *subject, *object, *access;
	int newfd;

	rules = g_new(struct _SmackRuleSet, 1);
	if (rules == NULL)
		return NULL;
	rules->rules = NULL;

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
		subject = strtok(buf, " \t\n");
		object = strtok(NULL, " \t\n");
		access = strtok(NULL, " \t\n");

		if (subject == NULL || object == NULL || access == NULL ||
		    strtok(NULL, " \t\n") != NULL) {
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
	g_list_free_full(handle->rules, g_free);
}

int smack_rule_set_save(SmackRuleSet handle, int fd)
{
	GList *entry;
	struct smack_rule *rule;
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

	entry = g_list_first(handle->rules);
	while (entry) {
		rule = entry->data;

		ac_to_config_str(rule->access_code, access_type);

		ret = fprintf(file, "%s %s %s\n",
			      rule->subject, rule->object, access_type);
		if (ret < 0) {
			ret = -1;
			goto out;
		}

		entry = g_list_next(entry);
	}

out:
	fclose(file);
	return ret;
}

int smack_rule_set_apply_kernel(SmackRuleSet handle, int fd)
{
	GList *entry;
	struct smack_rule *rule;
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

	entry = g_list_first(handle->rules);
	while (entry) {
		rule = entry->data;

		ac_to_kernel_str(rule->access_code, access_type);

		ret = fprintf(file, KERNEL_FORMAT "\n",
			      rule->subject, rule->object, access_type);
		if (ret < 0) {
			ret = -1;
			goto out;
		}

		entry = g_list_next(entry);
	}

out:
	fclose(file);
	return ret;
}

int smack_rule_set_clear_kernel(SmackRuleSet handle, int fd)
{
	GList *entry;
	struct smack_rule *rule;
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

	entry = g_list_first(handle->rules);
	while (entry) {
		rule = entry->data;

		ret = fprintf(file, KERNEL_FORMAT "\n",
			      rule->subject, rule->object, "-----");
		if (ret < 0) {
			ret = -1;
			goto out;
		}

		entry = g_list_next(entry);
	}

out:
	fclose(file);
	return ret;
}

int smack_rule_set_add(SmackRuleSet handle, const char *subject,
		       const char *object, const char *access_type)
{
	struct smack_rule *rule = NULL;

	if (strlen(subject) > LABEL_LEN || strlen(object) > LABEL_LEN) {
		errno = ERANGE;
		return -1;
	}

	rule = g_new(struct smack_rule, 1);
	if (rule == NULL)
		return -1;

	strncpy(rule->subject, subject, LABEL_LEN + 1);
	strncpy(rule->object, object, LABEL_LEN + 1);
	rule->access_code = str_to_ac(access_type);

	handle->rules = g_list_append(handle->rules, rule);

	return 0;
}

int smack_have_access(int fd, const char *subject,
		      const char *object, const char *access_type)
{
	char buf[LOAD_SIZE];
	int ret;

	ret = snprintf(buf, LOAD_SIZE, KERNEL_FORMAT, subject, object, access_type);
	if (ret < 0)
		return -1;

	if (ret != (LOAD_SIZE - 1)) {
		errno = ERANGE;
		return -1;
	}

	ret = write(fd, buf, LOAD_SIZE - 1);
	if (ret < 0)
		return -1;

	ret = read(fd, buf, 1);
	if (ret < 0)
		return -1;

	return buf[0] == '1';
}

char *smack_get_socket_label(int fd)
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
	str[4] = ((access & ACC_T) != 0) ? 't' : '-';
	str[5] = '\0';
}

