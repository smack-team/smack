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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <uthash.h>

#define SMACK_ACC_R 1
#define SMACK_ACC_W 2
#define SMACK_ACC_X 4
#define SMACK_ACC_A 16
#define SMACK_ACC_LEN 4

#define SMACK64 "security.SMACK64"
#define SMACK64_LEN 23

struct object_rule {
	char object[SMACK64_LEN + 1];
	unsigned ac;
	int dirty;
	UT_hash_handle object_hash;
};

struct subject_rule {
	char subject[SMACK64_LEN + 1];
	struct object_rule *objects;
	UT_hash_handle subject_hash;
};

struct smack_ruleset {
	struct subject_rule *subjects;
};

static struct object_rule *update_rule(struct smack_ruleset *rule_set,
					     const char *subject, const char *object,
					     unsigned ac);
inline struct subject_rule *find_subject_rules(struct smack_ruleset *rule_set, 
					     const char *subject);
inline struct object_rule *find_object_rule(struct subject_rule *rule,
					 	  const char *object);
inline unsigned str_to_ac(const char *str);
inline void ac_to_str(unsigned ac, char *str);

smack_ruleset_t smack_create_ruleset(void)
{
	struct smack_ruleset *result =
		calloc(1, sizeof(struct smack_ruleset));
	return result;
}

void smack_destroy_ruleset(smack_ruleset_t handle)
{
	struct subject_rule *srule, *next_srule;
	struct object_rule *orule, *next_orule;

	for (srule = handle->subjects; srule; srule = next_srule) {
		for (orule = srule->objects; orule; orule = next_orule) {
			next_orule = orule->object_hash.next;
			free(orule);
		}
		next_srule = srule->subject_hash.next;
		free(srule);
	}

	free(handle);
}

int smack_read_rules(smack_ruleset_t handle, const char *path,
		     const char *subject_filter)
{
	FILE *file;
	char subject[SMACK64_LEN + 1];
	char object[SMACK64_LEN + 1];
	char access_str[SMACK_ACC_LEN];
	unsigned access;
	int ret, sok, ook;

	file = fopen(path, "r");
	if (file == NULL)
		return errno;

	for (;;) {
		ret = fscanf(file, "%23s %23s %4s\n", subject, object,
			     access_str);
		if (ret == EOF)
			break;
		if (ret != 3)
			continue;

		if (subject_filter == NULL ||
		    strcmp(subject, subject_filter) == 0) {
			access = str_to_ac(access_str);
			update_rule(handle, subject, object, access);
		}
	}

	fclose(file);
	return 0;
}

int smack_write_rules(smack_ruleset_t handle, const char *path)
{
	struct subject_rule *srule;
	struct object_rule *orule;
	FILE *file;
	struct smack_ruleset *rule_set = handle;
	char access_str[6];
	int err;

	file = fopen(path, "w+");
	if (!file)
		return errno;

	for (srule = rule_set->subjects; srule; srule = srule->subject_hash.next) {
		for (orule = srule->objects; orule; orule = orule->object_hash.next) {
			if (orule->dirty)
				continue;

			ac_to_str(orule->ac, access_str);
			err = fprintf(file, "%-23s %-23s %4s\n", 
				      srule->subject,
				      orule->object, access_str);
			if (err < 0) {
				fclose(file);
				return errno;
			}
		}
	}

	fclose(file);
	return 0;
}

int smack_add_rule(smack_ruleset_t handle, const char *subject, 
		   const char *object, const char *access_str)
{
	unsigned access;
	access = str_to_ac(access_str);
	return (update_rule(handle, subject, object, access) ? 0 : -1);
}

void smack_remove_rule(smack_ruleset_t handle, const char *subject,
		       const char *object)
{
	struct subject_rule *srule;
	struct object_rule *orule;

	srule = find_subject_rules(handle, subject);
	if (srule == NULL)
		return;

	orule = find_object_rule(srule, object);
	if (orule == NULL)
		return;

	orule->dirty = 1;
}

void smack_remove_subject_rules(smack_ruleset_t handle, const char *subject)
{
	struct subject_rule *srule;
	struct object_rule *orule;

	srule = find_subject_rules(handle, subject);
	if (srule == NULL)
		return;

	for (orule = srule->objects; orule; orule = orule->object_hash.next)
		orule->dirty = 1;
}

void smack_remove_object_rules(smack_ruleset_t handle, const char *object)
{
	struct subject_rule *srule;
	struct object_rule *orule;

	for (srule = handle->subjects; srule; srule = srule->subject_hash.next) {
		orule = find_object_rule(srule, object);
		if (orule != NULL)
			orule->dirty = 1;
	}
}

int smack_have_access_rule(smack_ruleset_t handle, const char *subject,
			   const char *object, const char *access_str)
{
	struct subject_rule *srule;
	struct object_rule *orule;
	unsigned ac;

	ac = str_to_ac(access_str);

	srule = find_subject_rules(handle, subject);
	if (srule == NULL)
		return 0;

	orule = find_object_rule(srule, object);
	if (orule == NULL)
		return 0;

	if (orule->dirty)
		return 0;

	return ((orule->ac & ac) == ac);
}

int smack_set_smack(const char *path, const char *smack)
{
	size_t size;
	int ret;

	size = strlen(smack);
	if (size > SMACK64_LEN)
		return -1;

	ret = setxattr(path, SMACK64, smack, size, 0);

	return ret;
}

int smack_get_smack(const char *path, char **smack)
{
	ssize_t ret;
	char *buf;

	ret = getxattr(path, SMACK64, NULL, 0);
	if (ret < 0)
		return -1;

	buf = malloc(ret + 1);
	ret = getxattr(path, SMACK64, buf, ret);
	if (ret < 0) {
		free(buf);
		return -1;
	}

	buf[ret] = '\0';
	*smack = buf;
	return 0;
}

static struct object_rule *update_rule(struct smack_ruleset *rule_set,
				       const char *subject,
				       const char *object, unsigned ac)
{
	struct subject_rule *srule;
	struct object_rule *orule;

	srule = find_subject_rules(rule_set, subject);
	if (srule == NULL) {
		srule = calloc(1, sizeof(struct subject_rule));
		strcpy(srule->subject, subject);
		HASH_ADD(subject_hash, rule_set->subjects, subject,
			 strlen(srule->subject), srule);
	}

	orule = find_object_rule(srule, object);
	if (orule == NULL) {
		orule = calloc(1, sizeof(struct object_rule));
		strcpy(orule->object, object);
		HASH_ADD(object_hash, srule->objects, object,
			 strlen(orule->object), orule);
	}

	orule->dirty = 0;
	orule->ac = ac;
	return orule;
}

inline struct subject_rule *find_subject_rules(struct smack_ruleset *rule_set,
					       const char *subject)
{
	struct subject_rule *rule;
	HASH_FIND(subject_hash, rule_set->subjects, subject, strlen(subject),
		  rule);
	return rule;
}

inline struct object_rule *find_object_rule(struct subject_rule *rule,
					    const char *object)
{
	struct object_rule *orule;
	HASH_FIND(object_hash, rule->objects, object, strlen(object),
		  orule);
	return orule;
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

inline void ac_to_str(unsigned access, char *str)
{
	str[0] = ((access & SMACK_ACC_R) != 0) ? 'r' : '-';
	str[1] = ((access & SMACK_ACC_W) != 0) ? 'w' : '-';
	str[2] = ((access & SMACK_ACC_X) != 0) ? 'x' : '-';
	str[3] = ((access & SMACK_ACC_A) != 0) ? 'a' : '-';
	str[4] = '\0';
}

