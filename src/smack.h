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
typedef struct _SmackRuleSet *SmackRuleSet;

/*!
 * smack_rule_set_apply flags.
 */
#define SMACK_RULE_SET_APPLY_CLEAR 0x01

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Creates a new SmackRuleSet instance. If fd >= 0, rule set is read from the
 * given file. Otherwise, empty rule set is created.
 *
 * @param fd file descriptor
 * @return SmackRuleSet instance on success
 */
extern SmackRuleSet smack_rule_set_new(int fd);

/*!
 * Destroy a SmackRuleSet instance.
 *
 * @param handle handle to a SmackRuleSet instance
 */
extern void smack_rule_set_free(SmackRuleSet handle);

/*!
 * Write access rules to a given file.
 *
 * @param handle handle to a rules
 * @param fd file descriptor
 * @return Returns 0 on success.
 */
extern int smack_rule_set_save(SmackRuleSet handle, int fd);

/*!
 * Write rules to kernel.
 *
 * @param handle handle to a rules
 * @param flags apply flags
 * @return Returns 0 on success.
 */
extern int smack_rule_set_apply(SmackRuleSet handle, int flags);

/*!
 * Add new rule to a rule set.
 *
 * @param handle handle to a rule set
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access_type access type
 * @return Returns 0 on success.
 */
extern int smack_rule_set_add(SmackRuleSet handle, const char *subject,
			      const char *object, const char *access_type);

/*!
 * Check Smack access.
 *
 * @param fd file descriptor
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access_type access type
 * @return 1 if access, 0 if no access and -1 on error.
 */
extern int smack_have_access(const char *subject, const char *object,
			     const char *access_type);

/*!
  * Get the label that is associated with a peer on the other end of an
  * Unix socket. Caller is responsible of freeing the returned label.
  *
  * @param fd socket file descriptor
  * @return label on success and NULL of failure.
  */
extern char *smack_get_peer_label(int fd);

#ifdef __cplusplus
}
#endif

#endif // SMACK_H
