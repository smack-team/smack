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
#include "smack_internal.h"

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
					  const char *subject_filter,
					  SmackLabelSet labels)
{
	SmackRuleSet rules;
	FILE *file;
	char *buf = NULL;
	const char *subject, *object, *access;
	const char *sstr, *ostr;
	unsigned ac;
	size_t size;
	int err, ret;

	file = fopen(path, "r");
	if (file == NULL)
		return NULL;

	rules = smack_rule_set_new();
	if (rules == NULL) {
		fclose(file);
		return NULL;
	}

	ret = 0;

	while (getline(&buf, &size, file) != -1) {
		subject = strtok(buf, " \t\n");
		object = strtok(NULL, " \t\n");
		access = strtok(NULL, " \t\n");

		if (subject == NULL || object == NULL || access == NULL ||
		    strtok(NULL, " \t\n") != NULL) {
			ret = -1;
			break;
		}

		if (labels != NULL) {
			sstr = smack_label_set_to_short_name(labels, subject);
			ostr = smack_label_set_to_short_name(labels, object);
		} else {
			sstr = subject;
			ostr = object;
		}

		if (sstr == NULL || ostr == NULL) {
			ret = -1;
			break;
		}

		if (subject_filter == NULL ||
			 strcmp(sstr, subject_filter) == 0) {
			ac = str_to_ac(access);
			err = update_rule(&rules->subjects, sstr, ostr,
					  ac);
			if (err != 0) {
				ret = -1;
				break;
			}
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

int smack_rule_set_save_to_file(SmackRuleSet handle, const char *path,
			        SmackLabelSet labels)
{
	struct smack_subject *s, *stmp;
	struct smack_object *o, *otmp;
	const char *sstr, *ostr;
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

			if (labels != NULL) {
				sstr = smack_label_set_to_long_name(labels, s->subject);
				ostr = smack_label_set_to_long_name(labels, o->object);
			} else {
				sstr = s->subject;
				ostr = o->object;
			}

			if (sstr == NULL || ostr == NULL) {
				ret = -1;
				goto out;
			}

			ac_to_config_str(o->ac, astr);

			err = fprintf(file, "%s %s %s\n",
				      sstr, ostr, astr);
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

int smack_rule_set_clear_from_kernel(SmackRuleSet handle, const char *path)
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
			ac_to_kernel_str(0, str);

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
		       const char *object, const char *access_str,
		       SmackLabelSet labels)
{
	unsigned access;
	int ret;

	if (labels != NULL) {
		subject = smack_label_set_to_short_name(labels, subject);
		object = smack_label_set_to_short_name(labels, object);

		if (subject == NULL || object == NULL)
			return -1;
	}

	access = str_to_ac(access_str);
	ret = update_rule(&handle->subjects, subject, object, access);
	return ret == 0 ? 0  : -1;
}

void smack_rule_set_remove(SmackRuleSet handle, const char *subject,
			   const char *object, SmackLabelSet labels)
{
	struct smack_subject *s = NULL;
	struct smack_object *o = NULL;

	if (labels != NULL) {
		subject = smack_label_set_to_short_name(labels, subject);
		object = smack_label_set_to_short_name(labels, object);

		if (subject == NULL || object == NULL)
			return;
	}

	HASH_FIND_STR(handle->subjects, subject, s);
	if (s == NULL)
		return;

	HASH_FIND_STR(s->objects, object, o);
	if (o == NULL)
		return;

	o->ac = 0;
	return;
}

void smack_rule_set_remove_by_subject(SmackRuleSet handle, const char *subject,
				      SmackLabelSet labels)
{
	struct smack_subject *s = NULL;
	struct smack_object *o = NULL, *tmp = NULL;

	if (labels != NULL) {
		subject = smack_label_set_to_short_name(labels, subject);

		if (subject == NULL)
			return;
	}

	HASH_FIND_STR(handle->subjects, subject, s);
	if (s == NULL)
		return;

	HASH_ITER(hh, s->objects, o, tmp)
		o->ac = 0;
}

void smack_rule_set_remove_by_object(SmackRuleSet handle, const char *object,
				     SmackLabelSet labels)
{
	struct smack_subject *s = NULL, *tmp = NULL;
	struct smack_object *o = NULL;

	if (labels != NULL) {
		object = smack_label_set_to_short_name(labels, object);

		if (object == NULL)
			return;
	}

	HASH_ITER(hh, handle->subjects, s, tmp) {
		HASH_FIND_STR(s->objects, object, o);
		if (o)
			o->ac = 0;
	}
}

int smack_rule_set_have_access(SmackRuleSet handle, const char *subject,
			       const char *object, const char *access_str,
			       SmackLabelSet labels)
{
	struct smack_subject *s = NULL;
	struct smack_object *o = NULL;
	unsigned ac;

	if (labels != NULL) {
		subject = smack_label_set_to_short_name(labels, subject);
		object = smack_label_set_to_short_name(labels, object);

		if (subject == NULL || object == NULL)
			return;
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
	str[i] = '\0';
}

inline void ac_to_kernel_str(unsigned access, char *str)
{
	str[0] = ((access & ACC_R) != 0) ? 'r' : '-';
	str[1] = ((access & ACC_W) != 0) ? 'w' : '-';
	str[2] = ((access & ACC_X) != 0) ? 'x' : '-';
	str[3] = ((access & ACC_A) != 0) ? 'a' : '-';
	str[4] = '\0';
}

