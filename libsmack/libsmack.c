/*
 * This file is part of libsmack
 *
 * Copyright (C) 2010, 2011 Nokia Corporation
 * Copyright (C) 2011, 2012, 2013 Intel Corporation
 * Copyright (C) 2012, 2013 Samsung Electronics Co.
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
 */

#define __GNU_SOURCE
#include <search.h>
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
#include <sys/xattr.h>

#define SELF_LABEL_FILE "/proc/self/attr/current"

#define SHORT_LABEL_LEN 23
#define ACC_LEN 6
#define LOAD_LEN (2 * (SMACK_LABEL_LEN + 1) + 2 * ACC_LEN + 1)
#define KERNEL_LONG_FORMAT "%s %s %s"
#define KERNEL_SHORT_FORMAT "%-23s %-23s %5.5s"
#define KERNEL_MODIFY_FORMAT "%s %s %s %s"

#define LEVEL_MAX 255
#define NUM_LEN 4
#define BUF_SIZE 512
#define CAT_MAX_COUNT 240
#define CAT_MAX_VALUE 63
#define CIPSO_POS(i)   (SMACK_LABEL_LEN + 1 + NUM_LEN + NUM_LEN + i * NUM_LEN)
#define CIPSO_MAX_SIZE CIPSO_POS(CAT_MAX_COUNT)
#define CIPSO_NUM_LEN_STR "%-4d"

#define ACCESS_TYPE_R 0x01
#define ACCESS_TYPE_W 0x02
#define ACCESS_TYPE_X 0x04
#define ACCESS_TYPE_A 0x08
#define ACCESS_TYPE_T 0x10
#define ACCESS_TYPE_L 0x20

#define DICT_HASH_SIZE 4096

extern char *smackfs_mnt;
extern int smackfs_mnt_dirfd;

struct label_dict {
	char **labels;
	int nof_labels;
	struct hsearch_data *htab;
};

struct smack_rule {
	int subject_id;
	int object_id;
	int subject_len;
	int object_len;
	int allow_code;
	int deny_code;
	struct smack_rule *next;
};

struct smack_accesses {
	struct smack_rule *first;
	struct smack_rule *last;
	struct label_dict *dict;
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
static inline ssize_t get_label(char *dest, const char *src);
static inline int str_to_access_code(const char *str);
static inline void access_code_to_str(unsigned code, char *str);
static int dict_create(struct label_dict **dict);
static int dict_free(struct label_dict *dict);
static const char *dict_get_label(const struct label_dict *dict, int id);
static ssize_t dict_add_label(struct label_dict *dict, int *id, const char *src);

int smack_accesses_new(struct smack_accesses **accesses)
{
	struct smack_accesses *result;

	result = calloc(sizeof(struct smack_accesses), 1);
	if (result == NULL)
		return -1;

	if (dict_create(&(result->dict)))
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

	dict_free(handle->dict);
	free(handle);
}

int smack_accesses_save(struct smack_accesses *handle, int fd)
{
	struct smack_rule *rule = handle->first;
	char allow_str[ACC_LEN + 1];
	char deny_str[ACC_LEN + 1];
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
		access_code_to_str(rule->allow_code, allow_str);

		if (rule->deny_code != -1) /* modify? */ {
			access_code_to_str(rule->deny_code, deny_str);

			ret = fprintf(file, "%s %s %s %s\n",
				      dict_get_label(handle->dict, rule->subject_id),
				      dict_get_label(handle->dict, rule->object_id),
				      allow_str, deny_str);
		} else {
			ret = fprintf(file, "%s %s %s\n",
				      dict_get_label(handle->dict, rule->subject_id),
				      dict_get_label(handle->dict, rule->object_id),
				      allow_str);
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

	rule->subject_len = dict_add_label(handle->dict, &(rule->subject_id), subject);
	rule->object_len = dict_add_label(handle->dict, &(rule->object_id), object);
	if (rule->subject_len < 0 || rule->object_len < 0) {
		free(rule);
		return -1;
	}

	rule->allow_code = str_to_access_code(access_type);
	rule->deny_code = -1; /* no modify */
	if (rule->allow_code == -1) {
		free(rule);
		return -1;
	}

	if (handle->first == NULL) {
		handle->first = handle->last = rule;
	} else {
		handle->last->next = rule;
		handle->last = rule;
	}

	return 0;
}

int smack_accesses_add_modify(struct smack_accesses *handle,
			      const char *subject,
			      const char *object,
			      const char *allow_access_type,
			      const char *deny_access_type)
{
	struct smack_rule *rule = NULL;

	rule = calloc(sizeof(struct smack_rule), 1);
	if (rule == NULL)
		return -1;

	rule->subject_len = dict_add_label(handle->dict, &(rule->subject_id), subject);
	rule->object_len = dict_add_label(handle->dict, &(rule->object_id), object);
	if (rule->subject_len < 0 || rule->object_len < 0) {
		free(rule);
		return -1;
	}

	rule->allow_code = str_to_access_code(allow_access_type);
	rule->deny_code = str_to_access_code(deny_access_type);
	if (rule->allow_code == -1 || rule->deny_code == -1) {
		free(rule);
		return -1;
	}

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
	char buf[LOAD_LEN + 1];
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

	while (fgets(buf, LOAD_LEN + 1, file) != NULL) {
		if (strcmp(buf, "\n") == 0)
			continue;
		subject = strtok_r(buf, " \t\n", &ptr);
		object = strtok_r(NULL, " \t\n", &ptr);
		access = strtok_r(NULL, " \t\n", &ptr);
		access2 = strtok_r(NULL, " \t\n", &ptr);

		if (subject == NULL || object == NULL || access == NULL ||
		    strtok_r(NULL, " \t\n", &ptr) != NULL) {
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
	char str[ACC_LEN + 1];
	int code;
	int ret;
	int fd;
	int access2 = 1;

	if (smackfs_mnt_dirfd < 0)
		return -1;

	fd = openat(smackfs_mnt_dirfd, "access2", O_RDWR);
	if (fd < 0) {
		if (errno != ENOENT)
			return -1;
		
		fd = openat(smackfs_mnt_dirfd, "access", O_RDWR);
		if (fd < 0)
			return -1;
		access2 = 0;
	}

	if ((code = str_to_access_code(access_type)) < 0)
		return -1;
	access_code_to_str(code, str);

	if (access2)
		ret = snprintf(buf, LOAD_LEN + 1, KERNEL_LONG_FORMAT,
			       subject, object, str);
	else
		ret = snprintf(buf, LOAD_LEN + 1, KERNEL_SHORT_FORMAT,
			       subject, object, str);

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

	free(cipso);
}

int smack_cipso_apply(struct smack_cipso *cipso)
{
	struct cipso_mapping *m = NULL;
	char buf[CIPSO_MAX_SIZE];
	int fd;
	int i;
	int offset;

	if (smackfs_mnt_dirfd < 0)
		return -1;

	fd = openat(smackfs_mnt_dirfd, "cipso2", O_WRONLY);
	if (fd < 0)
		return -1;

	memset(buf,0,CIPSO_MAX_SIZE);
	for (m = cipso->first; m != NULL; m = m->next) {
		snprintf(buf, SMACK_LABEL_LEN + 1, "%s", m->label);
		offset = strlen(buf) + 1;

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

		if (level == NULL || get_label(mapping->label, label) < 0)
			goto err_out;

		errno = 0;
		val = strtol(level, NULL, 10);
		if (errno)
			goto err_out;

		if (val < 0 || val > LEVEL_MAX)
			goto err_out;

		mapping->level = val;

		for (i = 0; i < CAT_MAX_COUNT && cat != NULL; i++) {
			errno = 0;
			val = strtol(cat, NULL, 10);
			if (errno)
				goto err_out;

			if (val < 0 || val > CAT_MAX_VALUE)
				goto err_out;

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
	return smackfs_mnt;
}

ssize_t smack_new_label_from_self(char **label)
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
	return ret;
}

ssize_t smack_new_label_from_socket(int fd, char **label)
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
	return length;
}

ssize_t smack_new_label_from_path(const char *path, const char *xattr, 
				  int follow, char **label)
{
	char buf[SMACK_LABEL_LEN + 1];
	char *result;
	ssize_t ret = 0;

	ret = follow ?
		getxattr(path, xattr, buf, SMACK_LABEL_LEN + 1) :
		lgetxattr(path, xattr, buf, SMACK_LABEL_LEN + 1);
	if (ret < 0)
		return -1;

	result = calloc(ret + 1, 1);
	if (result == NULL)
		return -1;

	ret = get_label(result, buf);
	if (ret < 0) {
		free(result);
		return -1;
	}

	*label = result;
	return ret;
}

int smack_set_label_for_self(const char *label)
{
	int len;
	int fd;
	int ret;

	len = get_label(NULL, label);
	if (len < 0)
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

	if (smackfs_mnt_dirfd < 0)
		return -1;

	len = get_label(NULL, subject);
	if (len < 0)
		return -1;

	fd = openat(smackfs_mnt_dirfd, "revoke-subject", O_WRONLY);
	if (fd < 0)
		return -1;

	ret = write(fd, subject, len);
	close(fd);

	return (ret < 0) ? -1 : 0;
}

static int accesses_apply(struct smack_accesses *handle, int clear)
{
	char buf[LOAD_LEN + 1];
	char allow_str[ACC_LEN + 1];
	char deny_str[ACC_LEN + 1];
	struct smack_rule *rule;
	int ret;
	int fd;
	int load_fd;
	int change_fd;
	int load2 = 1;

	if (smackfs_mnt_dirfd < 0)
		return -1;

	load_fd = openat(smackfs_mnt_dirfd, "load2", O_WRONLY);
	if (load_fd < 0) {
		if (errno != ENOENT)
			return -1;
		/* fallback */
		load_fd = openat(smackfs_mnt_dirfd, "load", O_WRONLY);
		/* Try to continue if the file doesn't exist, we might not need it. */
		if (load_fd < 0 && errno != ENOENT)
			return -1;
		load2 = 0;
	}

	change_fd = openat(smackfs_mnt_dirfd, "change-rule", O_WRONLY);
	/* Try to continue if the file doesn't exist, we might not need it. */
	if (change_fd < 0 && errno != ENOENT) {
		ret = -1;
		goto err_out;
	}

	for (rule = handle->first; rule != NULL; rule = rule->next) {
		/* Fail immediately without doing any further processing
		   if modify rules are not supported. */
		if (rule->deny_code >= 0 && change_fd < 0) {
			ret = -1;
			goto err_out;
		}

		access_code_to_str(clear ? 0 : rule->allow_code, allow_str);

		if (rule->deny_code != -1 && !clear) {
			access_code_to_str(rule->deny_code, deny_str);

			fd = change_fd;
			ret = snprintf(buf, LOAD_LEN + 1, KERNEL_MODIFY_FORMAT,
				       dict_get_label(handle->dict, rule->subject_id),
				       dict_get_label(handle->dict, rule->object_id),
				       allow_str,
				       deny_str);
		} else {
			fd = load_fd;
			if (load2)
				ret = snprintf(buf, LOAD_LEN + 1, KERNEL_LONG_FORMAT,
					       dict_get_label(handle->dict, rule->subject_id),
					       dict_get_label(handle->dict, rule->object_id),
					       allow_str);
			else {
				if (rule->subject_len > SHORT_LABEL_LEN ||
				    rule->object_len > SHORT_LABEL_LEN) {
					ret = -1;
					goto err_out;
				}

				ret = snprintf(buf, LOAD_LEN + 1, KERNEL_SHORT_FORMAT,
					       dict_get_label(handle->dict, rule->subject_id),
					       dict_get_label(handle->dict, rule->object_id),
					       allow_str);
			}
		}

		if (ret < 0) {
			ret = -1;
			goto err_out;
		}

		ret = write(fd, buf, ret);
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

static inline ssize_t get_label(char *dest, const char *src)
{
	int i;

	if (!src || src[0] == '\0' || src[0] == '-')
		return -1;

	for (i = 0; i < (SMACK_LABEL_LEN + 1) && src[i]; i++) {
		if (src[i] <= ' ' || src[i] > '~')
			return -1;
		switch (src[i]) {
		case '/':
		case '"':
		case '\\':
		case '\'':
			return -1;
		default:
			break;
		}

		if (dest)
			dest[i] = src[i];
	}

	if (dest && i < (SMACK_LABEL_LEN + 1))
		dest[i] = '\0';

	return i < (SMACK_LABEL_LEN + 1) ? i : -1;
}


static inline int str_to_access_code(const char *str)
{
	int i;
	unsigned int code = 0;

	for (i = 0; str[i] != '\0'; i++) {
		switch (str[i]) {
		case 'r':
		case 'R':
			code |= ACCESS_TYPE_R;
			break;
		case 'w':
		case 'W':
			code |= ACCESS_TYPE_W;
			break;
		case 'x':
		case 'X':
			code |= ACCESS_TYPE_X;
			break;
		case 'a':
		case 'A':
			code |= ACCESS_TYPE_A;
			break;
		case 't':
		case 'T':
			code |= ACCESS_TYPE_T;
			break;
		case 'l':
		case 'L':
			code |= ACCESS_TYPE_L;
			break;
		case '-':
			break;
		default:
			return -1;
		}
	}

	return code;
}

static inline void access_code_to_str(unsigned int code, char *str)
{
	str[0] = ((code & ACCESS_TYPE_R) != 0) ? 'r' : '-';
	str[1] = ((code & ACCESS_TYPE_W) != 0) ? 'w' : '-';
	str[2] = ((code & ACCESS_TYPE_X) != 0) ? 'x' : '-';
	str[3] = ((code & ACCESS_TYPE_A) != 0) ? 'a' : '-';
	str[4] = ((code & ACCESS_TYPE_T) != 0) ? 't' : '-';
	str[5] = ((code & ACCESS_TYPE_L) != 0) ? 'l' : '-';
	str[6] = '\0';
}

static int dict_create(struct label_dict **dict)
{
	*dict = calloc(1, sizeof(struct label_dict));
	if (!*dict)
		goto err;
	(*dict)->htab = calloc(1, sizeof(struct hsearch_data));
	if (!(*dict)->htab)
		goto free_dict;
	(*dict)->labels = calloc(DICT_HASH_SIZE, sizeof(char *));
	if (!(*dict)->labels)
		goto free_htab;
	if (hcreate_r(DICT_HASH_SIZE, (*dict)->htab) == 0)
		goto free_labels;
	return 0;

free_labels:
	free((*dict)->labels);
free_htab:
	free((*dict)->htab);
free_dict:
	free(*dict);
err:
	return -1;
}

static int dict_free(struct label_dict *dict)
{
	int i;
	for (i = 0; i < (dict->nof_labels); i++)
		free((dict->labels)[i]);
	free(dict->labels);
	hdestroy_r(dict->htab);
	free(dict->htab);
	free(dict);
	return 0;
}

static ssize_t dict_add_label(struct label_dict *dict, int *id, const char *label)
{
	ENTRY e, *ep;
	int ret, search;

	ret = get_label(NULL, label);

	if (dict->nof_labels == DICT_HASH_SIZE)
		return -2;
	if (ret == -1)
		return -1;

	e.key =  (char *)label;
	e.data = (void *)(&(dict->labels[dict->nof_labels]));

	search = hsearch_r(e, ENTER, &ep, dict->htab);
	if (search == 0)
		return -2;
	if (e.data != ep->data) {/*found an existing entry*/
		*id = (int)((char **)(ep->data) - dict->labels);
	} else {/*new entry added*/
		ep->key = malloc(ret + 1);
		if (!ep->key)
			return -3;
		ep->key[ret] = '\0';
		memcpy(ep->key, label, ret);
		dict->labels[dict->nof_labels] = ep->key;
		*id = dict->nof_labels++;
	}
	return ret;
}

static const char *dict_get_label(const struct label_dict *dict, int id)
{
	if (id < dict->nof_labels)
		return dict->labels[id];
	else
		return NULL;
}
