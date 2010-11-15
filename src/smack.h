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

/*!
 * @file smack.h
 *
 * Smack user space library
 *
 * Processes Smack rules both from smackfs and configuration files.
 */

#ifndef SMACK_H
#define SMACK_H

/*!
 * Handle to a in-memory representation of set of Smack rules.
 */
typedef struct smack_ruleset *smack_ruleset_t;

typedef struct smack_users *smack_users_t;

#define SMACK_FORMAT_CONFIG 0
#define SMACK_FORMAT_KERNEL 1

#define SMACK_SET_SYMLINK 1

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Create a new rule set. The returned rule set must be freed with
 * smack_destroy_ruleset().
 *
 * @return handle to the rule set. Returns NULL if allocation fails.
 */
extern smack_ruleset_t smack_create_ruleset(void);

/*!
 * Free resources allocated by ruleset.
 *
 * @param handle handle to a ruleset
 */
extern void smack_destroy_ruleset(smack_ruleset_t handle);

/*!
 * Read rules from a given file. Rules can be optionally filtered with a
 * subject.
 *
 * @param handle handle to a ruleset
 * @param path path to the file containing rules
 * @param subject read only rules for the given subject if not set to NULL.
 * @return 0 on success
 */
extern int smack_read_rules(smack_ruleset_t handle,
			    const char *path,
			    const char *subject);

/*!
 * Write rules to a given file.
 *
 * @param handle handle to a ruleset
 * @param path path to the rules file
 * @param format file format
 * @return 0 on success
 */
extern int smack_write_rules(smack_ruleset_t handle, const char *path,
			     int format);

/*!
 * Add new rule to a rule set.
 *
 * @param handle handle to a ruleset
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access string defining access type
 * @return 0 on success
 */
extern int smack_add_rule(smack_ruleset_t handle, const char *subject,
			  const char *object, const char *access);

/*!
 * Remove rule from a rule set.
 *
 * @param handle handle to a ruleset
 * @param subject subject of the rule
 * @param object object of the rule
 */
extern void smack_remove_rule(smack_ruleset_t handle, const char *subject,
			      const char *object);

/*!
 * Remove all rules with the given subject from a rule set.
 *
 * @param handle handle to a ruleset
 * @param subject subject of the rule
 */
extern void smack_remove_subject_rules(smack_ruleset_t handle,
				       const char *subject);

/*!
 * Remove all rules with the given object from a rule set.
 *
 * @param handle handle to a ruleset
 * @param object object of the rule
 */
extern void smack_remove_object_rules(smack_ruleset_t handle,
				      const char *object);

/*!
 * Does the given subject have at least the given access to the given object?
 *
 * @param handle handle to a ruleset
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access string defining access type
 * @return boolean value
 */
extern int smack_have_access_rule(smack_ruleset_t handle, const char *subject,
				  const char *object, const char *access);
/*!
 * Create users database. The returned rule set must be freed with
 * smack_destroy_ruleset().
 *
 * @return handle to the users db. Returns NULL if creation fails.
 */
extern smack_users_t smack_create_users();

/*!
 * Free users database.
 *
 * @param handle handle to a ruleset
 */
extern void smack_destroy_users(smack_users_t handle);

/*!
 * Read users from a given file.
 *
 * @param handle handle to a users db
 * @param path path to the file containing users
 * @return 0 on success
 */
extern int smack_read_users(smack_users_t handle, const char *path);

/*!
 * Write users to a given file.
 *
 * @param handle handle to a users db
 * @param path path to the users file
 * @return 0 on success
 */
extern int smack_write_users(smack_users_t handle, const char *path);

/*!
 * Set SMACK64 security attribute for a given path.
 *
 * @param path path to a file
 * @param smack new value
 * @param flags set flags
 * @return 0 on success
 */
extern int smack_set_file_smack(const char *path, const char *smack,
				int flags);

/*!
 * Get SMACK64 security attribute for a given path.
 * Allocated memory must be freed by the caller.
 *
 * @param path path to a file
 * @param smack current value
 * @param flags set flags
 * @return 0 on success
 */
extern int smack_get_file_smack(const char *path, char **smack,
				int flags);

/*!
 * Get SMACK64 security attribute for a given pid.
 *
 * @param pid pid of a process
 * @param smack current value
 * @return 0 on success
 */
extern int smack_get_proc_smack(int pid, char **smack);

#ifdef __cplusplus
}
#endif

#endif // SMACK_H
