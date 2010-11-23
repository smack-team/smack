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

#define SMACK_ACC_R 1
#define SMACK_ACC_W 2
#define SMACK_ACC_X 4
#define SMACK_ACC_A 16
#define SMACK_ACC_LEN 4

struct smack_object {
	char *object;
	unsigned ac;
	UT_hash_handle hh;
};

struct smack_subject {
	char *subject;
	struct smack_object *objects;
	UT_hash_handle hh;
};

struct _SmackRuleSet {
	struct smack_subject *subjects;
	SmackLabelSet labels;
};

static int update_rule(struct smack_subject **subjects,
		       const char *subject_str, const char *object_str,
		       unsigned ac);
inline unsigned str_to_ac(const char *str);
inline void ac_to_config_str(unsigned ac, char *str);
inline void ac_to_kernel_str(unsigned ac, char *str);

SmackRuleSet smack_rule_set_new(void)
{
	struct _SmackRuleSet *result =
		calloc(1, sizeof(struct _SmackRuleSet));
	return result;
}

SmackRuleSet smack_rule_set_new_from_file(const char *path,
					  const char *subject_filter)
{
	SmackRuleSet rules;
	FILE *file;
	char *buf = NULL;
	const char *subject, *object, *access;
	unsigned ac;
	size_t size;
	int ret = 0;

	file = fopen(path, "r");
	if (file == NULL)
		return NULL;

	rules = smack_rule_set_new();
	if (rules == NULL) {
		fclose(file);
		return NULL;
	}

	while (ret == 0 && getline(&buf, &size, file) != -1) {
		subject = strtok(buf, " \t\n");
		object = strtok(NULL, " \t\n");
		access = strtok(NULL, " \t\n");

		if (subject == NULL || object == NULL || access == NULL ||
		    strtok(NULL, " \t\n") != NULL) {
			ret = -1;
		} else if (subject_filter == NULL ||
			 strcmp(subject, subject_filter) == 0) {
			ac = str_to_ac(access);
			ret = update_rule(&rules->subjects, subject, object,
					  ac);
		}

		free(buf);
		buf = NULL;
	}

	if (ret != 0 || ferror(file)) {
		smack_rule_set_delete(rules);
		rules = NULL;
	}

	free(buf);
	fclose(file);
	return rules;
}

void smack_rule_set_delete(SmackRuleSet handle)
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

void smack_rule_set_attach_label_set(SmackRuleSet rules,
				     SmackLabelSet labels)
{
	rules->labels = labels;
}

int smack_rule_set_save_to_file(SmackRuleSet handle, const char *path)
{
	struct smack_subject *s, *stmp;
	struct smack_object *o, *otmp;
	FILE *file;
	char str[SMACK_ACC_LEN + 1];
	int err = 0;

	file = fopen(path, "w+");
	if (!file)
		return -1;

	HASH_ITER(hh, handle->subjects, s, stmp) {
		HASH_ITER(hh, s->objects, o, otmp) {
			ac_to_config_str(o->ac, str);

			err = fprintf(file, "%s %s %s\n",
				      s->subject, o->object, str);

			if (err < 0) {
				fclose(file);
				return errno;
			}
		}
	}

	fclose(file);
	return 0;
}

int smack_rule_set_save_to_kernel(SmackRuleSet handle, const char *path)
{
	struct smack_subject *s, *stmp;
	struct smack_object *o, *otmp;
	FILE *file;
	char str[6];
	int err = 0;

	file = fopen(path, "w+");
	if (!file)
		return -1;

	HASH_ITER(hh, handle->subjects, s, stmp) {
		HASH_ITER(hh, s->objects, o, otmp) {
			ac_to_kernel_str(o->ac, str);

			err = fprintf(file, "%-23s %-23s %4s\n",
				      s->subject, o->object, str);

			if (err < 0) {
				fclose(file);
				return errno;
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

	if (handle->labels != NULL) {
		subject = smack_label_set_to_short_name(handle->labels, subject);
		object = smack_label_set_to_short_name(handle->labels, object);

		if (subject == NULL || object == NULL)
			return -1;
	}

	access = str_to_ac(access_str);
	ret = update_rule(&handle->subjects, subject, object, access);
	return ret == 0 ? 0  : -1;
}

int smack_rule_set_remove(SmackRuleSet handle, const char *subject,
			  const char *object)
{
	struct smack_subject *s = NULL;
	struct smack_object *o = NULL;

	if (handle->labels != NULL) {
		subject = smack_label_set_to_short_name(handle->labels, subject);
		object = smack_label_set_to_short_name(handle->labels, object);

		if (subject == NULL || object == NULL)
			return -1;
	}

	HASH_FIND_STR(handle->subjects, subject, s);
	if (s == NULL)
		return -1;

	HASH_FIND_STR(s->objects, object, o);
	if (o == NULL)
		return -1;

	HASH_DEL(s->objects, o);
	free(o);
	return 0;
}

void smack_rule_set_remove_by_subject(SmackRuleSet handle, const char *subject)
{
	struct smack_subject *s = NULL;
	struct smack_object *o = NULL, *tmp = NULL;

	if (handle->labels != NULL) {
		subject = smack_label_set_to_short_name(handle->labels, subject);

		if (subject == NULL)
			return;
	}

	HASH_FIND_STR(handle->subjects, subject, s);
	if (s == NULL)
		return;

	HASH_ITER(hh, s->objects, o, tmp) {
		HASH_DEL(s->objects, o);
		free(o);
	}
}

void smack_rule_set_remove_by_object(SmackRuleSet handle, const char *object)
{
	struct smack_subject *s = NULL, *tmp = NULL;
	struct smack_object *o = NULL;

	if (handle->labels != NULL) {
		object = smack_label_set_to_short_name(handle->labels, object);

		if (object == NULL)
			return;
	}

	HASH_ITER(hh, handle->subjects, s, tmp) {
		HASH_FIND_STR(s->objects, object, o);
		HASH_DEL(s->objects, o);
		free(o);
	}
}

int smack_rule_set_have_access(SmackRuleSet handle, const char *subject,
			       const char *object, const char *access_str)
{
	struct smack_subject *s = NULL;
	struct smack_object *o = NULL;
	unsigned ac;

	if (handle->labels != NULL) {
		subject = smack_label_set_to_short_name(handle->labels, subject);
		object = smack_label_set_to_short_name(handle->labels, object);

		if (subject == NULL || object == NULL)
			return -1;
	}

	ac = str_to_ac(access_str);

	HASH_FIND_STR(handle->subjects, subject, s);
	if (s == NULL)
		return 0;

	HASH_FIND_STR(s->objects, object, o);
	if (o == NULL)
		return 0;

	return ((o->ac & ac) == ac);
}

static int update_rule(struct smack_subject **subjects,
		       const char *subject_str,
		       const char *object_str, unsigned ac)
{
	struct smack_subject *s = NULL;
	struct smack_object *o = NULL;

	if (strlen(subject_str) > SMACK64_LEN &&
	    strlen(object_str) > SMACK64_LEN)
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
			access |= SMACK_ACC_R;
			break;
		case 'w':
		case 'W':
			access |= SMACK_ACC_W;
			break;
		case 'x':
		case 'X':
			access |= SMACK_ACC_X;
			break;
		case 'a':
		case 'A':
			access |= SMACK_ACC_A;
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
	if ((access & SMACK_ACC_R) != 0)
		str[i++] = 'r';
	if ((access & SMACK_ACC_W) != 0)
		str[i++] = 'w';
	if ((access & SMACK_ACC_X) != 0)
		str[i++] = 'x';
	if ((access & SMACK_ACC_A) != 0)
		str[i++] = 'a';
	str[i] = '\0';
}

inline void ac_to_kernel_str(unsigned access, char *str)
{
	str[0] = ((access & SMACK_ACC_R) != 0) ? 'r' : '-';
	str[1] = ((access & SMACK_ACC_W) != 0) ? 'w' : '-';
	str[2] = ((access & SMACK_ACC_X) != 0) ? 'x' : '-';
	str[3] = ((access & SMACK_ACC_A) != 0) ? 'a' : '-';
	str[4] = '\0';
}

