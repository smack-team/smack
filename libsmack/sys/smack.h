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
 */

/*!
 * Smack user space library
 */

#ifndef _SYS_SMACK_H
#define _SYS_SMACK_H

#include <sys/types.h>

/*!
 * Handle to a in-memory representation of set of Smack rules.
 */
struct smack_accesses;

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

#ifdef __cplusplus
}
#endif

#endif // _SYS_SMACK_H
