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

enum smack_label_type {
	SMACK_LABEL_ACCESS,
	SMACK_LABEL_EXEC,
	SMACK_LABEL_MMAP,
	SMACK_LABEL_TRANSMUTE,
	SMACK_LABEL_IPIN,
	SMACK_LABEL_IPOUT,
};

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

struct smack_cipso *smack_cipso_new(int fd);

void smack_cipso_free(struct smack_cipso *cipso);

int smack_cipso_apply(struct smack_cipso *cipso);

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

/*!
 * Get SMACK label from file.
 * On successful call label will be stored on allocated memory.
 * Caller should take care of freeing that memory later.
 *
 * @param path file system path
 * @param label returned label
 * @param type label type to get
 * @return 0 on success and negative value on failure.
 */
int smack_getlabel(const char *path, char** label,
		enum smack_label_type type);

/*!
 * Get SMACK label from file. If path points to a symbolic link, the
 * function will return label of the link instead of file it refers to.
 * On successful call label will be stored on allocated memory.
 * Caller should take care of freeing that memory later.
 *
 * @param path file system path
 * @param label returned label
 * @param type label type to get
 * @return 0 on success and negative value on failure.
 */
int smack_lgetlabel(const char *path, char** label,
		enum smack_label_type type);

/*!
 * Get SMACK label from file descriptor.
 * On successful call label will be stored on allocated memory.
 * Caller should take care of freeing that memory later.
 *
 * @param fd file descriptor
 * @param label returned label
 * @param type label type to get
 * @return 0 on success and negative value on failure.
 */
int smack_fgetlabel(int fd, char** label,
		enum smack_label_type type);

/*!
 * Set SMACK label for file.
 * On successful call label will be stored on allocated memory.
 *
 * @param path file system path
 * @param label SMACK label to set
 *   if equal to NULL or "", label will be removed
 *   for type SMACK_LABEL_TRANSMUTE valid values are NULL, "", "0" or "1"
 * @param type label type to get
 * @return 0 on success and negative value on failure.
 */
int smack_setlabel(const char *path, const char* label,
		enum smack_label_type type);

/*!
 * Set SMACK label for file. If path points to a symbolic link, the
 * function will set label of the link instead of file it refers to.
 *
 * @param path file system path
 * @param label SMACK label to set
 *   if equal to NULL or "", label will be removed
 *   for type SMACK_LABEL_TRANSMUTE valid values are NULL, "", "0" or "1"
 * @param type label type to get
 * @return 0 on success and negative value on failure.
 */
int smack_lsetlabel(const char *path, const char* label,
		enum smack_label_type type);

/*!
 * Get SMACK label from file descriptor.
 *
 * @param fd file descriptor
 * @param label SMACK label to set
 *   if equal to NULL or "", label will be removed
 *   for type SMACK_LABEL_TRANSMUTE valid values are NULL, "", "0" or "1"
 * @param type label type to get
 * @return 0 on success and negative value on failure.
 */
int smack_fsetlabel(int fd, const char* label,
		enum smack_label_type type);

#ifdef __cplusplus
}
#endif

#endif // _SYS_SMACK_H
