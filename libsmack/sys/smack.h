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
 * Allocates memory for a new empty smack_accesses instance. The returned
 * instance must be later freed with smack_accesses_free().
 *
 * @param handle output variable for the struct smack_accesses instance
 * @return Returns 0 on success and negative on failure. If the operation
 * is succesful 'accesses' variable will contain a valid pointer.
 */
int smack_accesses_new(struct smack_accesses **handle);

/*!
 * Destroys a struct smack_accesses instance.
 *
 * @param handle handle to a struct smack_accesses instance
 */
void smack_accesses_free(struct smack_accesses *handle);

/*!
 * Write access rules to a given file.
 *
 * @param handle handle to a struct smack_accesses instance
 * @param fd file descriptor to the open file
 * @return Returns 0 on success and negative on failure.
 */
int smack_accesses_save(struct smack_accesses *handle, int fd);

/*!
 * Apply access rules to the kernel. Rules are applied in the order that
 * they were added.
 *
 * @param handle handle to a struct smack_accesses instance
 * @return Returns 0 on success and negative on failure.
 */
int smack_accesses_apply(struct smack_accesses *handle);

/*!
 * Clear access rules from the kernel. Clears the rules by writing
 * corresponding rules with zero access. Note that this function
 * does not check whether the rules pre-exist or not.
 *
 * @param handle handle to a struct smack_accesses instance
 * @return Returns 0 on success and negative on failure.
 */
int smack_accesses_clear(struct smack_accesses *handle);

/*!
 * Add a new rule to the given access rules.
 *
 * @param handle handle to a struct smack_accesses instance
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access_type access type
 * @return Returns 0 on success and negative on failure.
 */
int smack_accesses_add(struct smack_accesses *handle, const char *subject,
		       const char *object, const char *access_type);

/*!
 * Add a modification rule to the given access rules. A modification rule
 * is written to the kernel file 'change-rule' when you apply rules with
 * smack_accesses_apply(). It can be used to turn on and off a certain access
 * type like write access.
 *
 * When a modification rule is applied to the kernel it will turn on access
 * types in allow_access and turn off access types in deny_access.
 *
 * @param handle handle to a struct smack_accesses instance
 * @param subject subject of the rule
 * @param object object of the rule
 * @param allow_access_type access type to be turned on
 * @param deny_access_type access type to be turned off
 * @return Returns 0 on success and negative on failure.
 */
int smack_accesses_add_modify(struct smack_accesses *handle,
			      const char *subject,
			      const char *object,
			      const char *allow_access_type,
			      const char *deny_access_type);

/*!
 * Load access rules from the given file.
 *
 * @param handle handle to a struct smack_accesses instance
 * @param fd file descriptor
 * @return Returns 0 on success and negative on failure.
 */
int smack_accesses_add_from_file(struct smack_accesses *handle, int fd);

/*!
 * Check whether SMACK allows access for given subject, object and requested
 * access.
 *
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access_type requested access type
 * @return Returns 1 if access is allowed, 0 if access is not allowed and
 * negative on error.
 */
int smack_have_access(const char *subject, const char *object,
		      const char *access_type);

/*!
 * Allocates memory for a new empty smack_cipso instance. The returned
 * instance must be later freed with smack_cipso_free().
 *
 * @param handle output variable for the struct smack_cipso instance
 * @return Returns 0 on success and negative on failure. If the operation
 * is succesful 'cipso' variable will contain a valid pointer.
 */
int smack_cipso_new(struct smack_cipso **handle);

/*!
 * Destroys a struct smack_cipso instance.
 *
 * @param handle handle to a struct smack_cipso instance
 */
void smack_cipso_free(struct smack_cipso *handle);

/*!
 * Apply CIPSO rules to the kernel.
 *
 * @param handle handle to a struct smack_cipso instance
 * @return Returns 0 on success and negative on failure.
 */
int smack_cipso_apply(struct smack_cipso *handle);

/*!
 * Add CIPSO rules from the given file.
 *
 * @param handle handle to a struct smack_cipso instance
 * @param fd file descriptor
 * @return Returns 0 on success and negative on failure.
 */
int smack_cipso_add_from_file(struct smack_cipso *handle, int fd);

/*!
 * Get pointer to a string containing path to the mounted SmackFS.
 *
 * @return Returns a string contain path to the mount SmackFS if SMACK is
 * enabled and SmackFS is mounted. Otherwise, NULL is returned.
 */
const char *smack_smackfs_path(void);

/*!
  * Get the label that is associated with the callers process.
  * Caller is responsible of freeing the returned label.
  *
  * @param label output variable for the label
  * @return Returns length of the label on success and negative value
  * on failure.
  */
ssize_t smack_new_label_from_self(char **label);

/*!
  * Get the label that is associated with a peer on the other end of a
  * UDS socket (SO_PEERSEC). Caller is responsible of freeing the returned
  * label.
  *
  * @param fd file descriptor of the socket
  * @param label output variable for the label
  * @return Returns length of the label on success and negative value
  * on failure.
  */
ssize_t smack_new_label_from_socket(int fd, char **label);

/*!
  * Get the SMACK label that is contained in an extended attribute.
  * Caller is responsible of freeing the returned label.
  *
  * @param path path of the file
  * @param xattr the extended attribute containing the SMACK label
  * @param follow whether or not to follow symbolic link
  * @param label output variable for the returned label
  * @return Returns length of the label on success and negative value
  * on failure.
  */
ssize_t smack_new_label_from_path(const char *path,
				  const char *xattr,
				  int follow,
				  char **label);

/*!
 * Set the label associated with the callers process. The caller must have
 * CAP_MAC_ADMIN POSIX capability in order to do this.
 *
 * @param label a string containing the new label
 * @return Returns 0 on success and negative on failure.
 */
int smack_set_label_for_self(const char *label);

/*!
 * Revoke all rules for the given subject label.
 *
 * @param subject subject to revoke
 * @return Returns 0 on success and negative on failure.
 */
int smack_revoke_subject(const char *subject);

#ifdef __cplusplus
}
#endif

#endif // _SYS_SMACK_H
