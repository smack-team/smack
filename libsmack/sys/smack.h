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
 * Rafal Krypa <r.krypa@samsung.com>
 */

/*!
 * Smack user space library
 */

#ifndef _SYS_SMACK_H
#define _SYS_SMACK_H

#include <sys/types.h>

/*!
 * Maximum length of a smack label, excluding terminating null character.
 */
#define SMACK_LABEL_LEN 255

/*!
 * Handle to a in-memory representation of set of Smack rules.
 */
struct smack_accesses;

/*!
 *
 */
struct smack_cipso;

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Creates a new empty smack_accesses instance.
 *
 * @param accesses created instance
 * @return 0 on success and negative value on failure.
 */
int smack_accesses_new(struct smack_accesses **accesses);

/*!
 * Destroy a struct smack_accesses *instance.
 *
 * @param handle handle to a struct smack_accesses *instance
 */
void smack_accesses_free(struct smack_accesses *handle);

/*!
 * Write access rules to a given file.
 *
 * @param handle handle to a rules
 * @param fd file descriptor
 * @return 0 on success and negative value on failure.
 */
int smack_accesses_save(struct smack_accesses *handle, int fd);

/*!
 * Write rules to kernel.
 *
 * @param handle handle to a rules
 * @return 0 on success and negative value on failure.
 */
int smack_accesses_apply(struct smack_accesses *handle);

/*!
 * Clear rules from kernel.
 *
 * @param handle handle to a rules
 * @return 0 on success and negative value on failure.
 */
int smack_accesses_clear(struct smack_accesses *handle);

/*!
 * Add new rule to a rule set.
 *
 * @param handle handle to a rule set
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access_type access type
 * @return Returns 0 on success.
 */
int smack_accesses_add(struct smack_accesses *handle, const char *subject,
		       const char *object, const char *access_type);

/*!
 * Add a modification rule to a rule set.
 * The modification rule will change access permissions for a given subject and
 * object.
 * If such rule already existend (in the kernel or earlier in the rule set),
 * it will be modified. Otherwise a new rule will be created, with permissions
 * from access_add minus permissions from access_del.
 *
 * @param handle handle to a rule set
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access_add access type
 * @param access_del access type
 * @return Returns 0 on success.
 */
int smack_accesses_add_modify(struct smack_accesses *handle, const char *subject,
		       const char *object, const char *access_add, const char *access_del);

/*!
 * Add rules from file.
 *
 * @param accesses instance
 * @param fd file descriptor
 * @return 0 on success and negative value on failure.
 */
int smack_accesses_add_from_file(struct smack_accesses *accesses, int fd);

/*!
 * Check for Smack access.
 *
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access_type access type
 * @return 1 if access, 0 if no access and -1 on error.
 */
int smack_have_access(const char *subject, const char *object,
		      const char *access_type);

/*!
 * Creates a new empty smack_cipso instance.
 *
 * @param cipso created instance
 * @return 0 on success and negative value on failure.
 */
int smack_cipso_new(struct smack_cipso **cipso);

/*!
 * Destroy a struct smack_cipso *instance.
 *
 * @param handle handle to a struct smack_cipso *instance
 */
void smack_cipso_free(struct smack_cipso *cipso);

/*!
 * Write rules to kernel.
 *
 * @param handle handle to a rules
 * @return 0 on success and negative value on failure.
 */
int smack_cipso_apply(struct smack_cipso *cipso);

/*!
 * Add rules from file.
 *
 * @param cipso instance
 * @param fd file descriptor
 * @return 0 on success and negative value on failure.
 */
int smack_cipso_add_from_file(struct smack_cipso *cipso, int fd);

/*!
 * Get the smackfs directory.
 */
const char *smack_smackfs_path(void);

/*!
  * Get the label that is associated with the callers process.
  * Caller is responsible of freeing the returned label.
  *
  * @param label returned label
  * @return 0 on success and negative value on failure.
  */
int smack_new_label_from_self(char **label);

/*!
  * Get the label that is associated with a peer on the other end of an
  * Unix socket (SO_PEERSEC). Caller is responsible of freeing the 
  * returned label.
  *
  * @param fd socket file descriptor
  * @param label returned label
  * @return 0 on success and negative value on failure.
  */
int smack_new_label_from_socket(int fd, char **label);

/*!
  * Get the SMACK label that is contained in an extended attribute.
  * Caller is responsible of freeing the returned label.
  *
  * @param path path of the file
  * @param xattr extended attribute containing the SMACK label
  * @param follow whether or not to follow symbolic link
  * @param label returned label
  * @return 0 on success and negative value on failure.
  */
int smack_new_label_from_path(const char *path,
			      const char *xattr,
			      int follow,
			      const char **label);

/*!
 * Set the label associated with the callers process.
 * Caller must be run by privileged user to succeed.
 *
 * @param label to set
 * @return 0 on success and negative value on failure.
 */
int smack_set_label_for_self(const char *label);

/*!
 * Revoke all rules for a subject label.
 *
 * @param subject subject to revoke
 * @return 0 on success and negative value on failure.
 */
int smack_revoke_subject(const char *subject);

#ifdef __cplusplus
}
#endif

#endif // _SYS_SMACK_H
