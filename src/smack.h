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
typedef struct _SmackRuleSet *SmackRuleSet;

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Read rules from a given file. Rules can be optionally filtered by a
 * subject.
 *
 * @param path path to the file containing rules. If NULL, empty set is
 * created.
 * @param subject read only rules for the given subject if not set to NULL.
 * @return SmackRuleSet instance on success
 */
extern SmackRuleSet smack_rule_set_new(const char *path,
				       const char *subject);

/*!
 * Free resources allocated by rules.
 *
 * @param handle handle to a rules
 */
extern void smack_rule_set_delete(SmackRuleSet handle);

/*!
 * Write access rules to a given file.
 *
 * @param handle handle to a rules
 * @param path path to the rules file
 * @return 0 on success
 */
extern int smack_rule_set_save_config(SmackRuleSet handle, const char *path);

/*!
 * Apply rules to kernel.
 *
 * @param handle handle to a rule set
 * @param path path to the SmackFS load file
 * @return 0 on success
 */
extern int smack_rule_set_apply_kernel(SmackRuleSet handle, const char *path);

/*!
 * Clear given set of rules from kernel.
 *
 * @param handle handle to a rules
 * @param path path to the rules file
 * @return 0 on success
 */
extern int smack_rule_set_clear_kernel(SmackRuleSet handle, const char *path);

/*!
 * Add new rule to a rule set. Updates existing rule if there is already rule
 * for the given subject and object.
 *
 * @param handle handle to a rule set
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access access string (rwxa)
 * @return 0 on success
 */
extern int smack_rule_set_add(SmackRuleSet handle, const char *subject,
			      const char *object, const char *access);

/*!
 * Remove rule from a rule set. When rules are applied to kernel, removed
 * rules will be written with empty access code.
 *
 * @param handle handle to a rule set
 * @param subject subject of the rule
 * @param object object of the rule
 * @return 0 on success
 */
extern void smack_rule_set_remove(SmackRuleSet handle, const char *subject,
				  const char *object);

/*!
 * Remove all rules with the given subject from a rule set. When rules are
 * applied to kernel, removed rules will be written with empty access code.
 *
 * @param handle handle to a rule set
 * @param subject subject of the rule
 */
extern void smack_rule_set_remove_by_subject(SmackRuleSet handle,
					     const char *subject);

/*!
 * Remove all rules with the given object from a rule set. When rules are
 * applied to kernel, removed rules will be written with empty access code.
 
 * @param handle handle to a rule set
 * @param object object of the rule
 */
extern void smack_rule_set_remove_by_object(SmackRuleSet handle,
					    const char *object);

/*!
 * Check access to a give object from the give rule set.
 *
 * @param handle handle to a rule set
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access string defining access type
 * @return 1 if access, 0 if no access and negative number of failure.
 */
extern int smack_rule_set_have_access(SmackRuleSet handle, const char *subject,
				      const char *object, const char *access);

#ifdef __cplusplus
}
#endif

#endif // SMACK_H
