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
 * Extended attributes.
 */
#define SMACK64 "security.SMACK64"
#define SMACK64EXEC "security.SMACK64EXEC"

/*!
 * Handle to a in-memory representation of set of Smack rules.
 */
typedef struct _SmackRuleSet *SmackRuleSet;

/*!
 * Handle to a in-memory representation for long label to 
 * short label mapping.
 */
typedef struct _SmackLabelSet *SmackLabelSet;

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Create a new rule set. The returned rule set must be freed with
 * smack_rule_set_delete().
 *
 * @return handle to the rule set. Returns NULL if allocation fails.
 */
extern SmackRuleSet smack_rule_set_new(void);

/*!
 * Read rules from a given file. Rules can be optionally filtered by a
 * subject.
 *
 * @param path path to the file containing rules
 * @param subject read only rules for the given subject if not set to NULL.
 * @return SmackRuleSet instance on success
 */
extern SmackRuleSet smack_rule_set_new_from_file(const char *path,
						 const char *subject);

/*!
 * Free resources allocated by rules.
 *
 * @param handle handle to a rules
 */
extern void smack_rule_set_delete(SmackRuleSet handle);

/*!
 * Attach label set to rule set to enabled transparent long name conversion.
 * Note: does not take ownership of label set so caller must take care of 
 * freeing it.
 *
 * @param rules rule set
 * @param labels label set
 */
extern void smack_rule_set_attach_label_set(SmackRuleSet rules,
					    SmackLabelSet labels);

/*!
 * Write rules to a given file.
 *
 * @param handle handle to a rules
 * @param path path to the rules file
 * @return 0 on success
 */
extern int smack_rule_set_save_to_file(SmackRuleSet handle, const char *path);

/*!
 * Write rules to SmackFS rules file.
 *
 * @param handle handle to a rules
 * @param path path to the rules file
 * @return 0 on success
 */
extern int smack_rule_set_save_to_kernel(SmackRuleSet handle, const char *path);

/*!
 * Add new rule to a rule set. Updates existing rule if there is already rule
 * for the given subject and object.
 *
 * @param handle handle to a rules
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access string defining access type
 * @return 0 on success
 */
extern int smack_rule_set_add(SmackRuleSet handle, const char *subject,
			      const char *object, const char *access);

/*!
 * Remove rule from a rule set.
 *
 * @param handle handle to a rules
 * @param subject subject of the rule
 * @param object object of the rule
 * @return 0 if user was found from user db.
 */
extern int smack_rule_set_remove(SmackRuleSet handle, const char *subject,
				 const char *object);

/*!
 * Remove all rules with the given subject from a rule set.
 *
 * @param handle handle to a rules
 * @param subject subject of the rule
 */
extern void smack_rule_set_remove_by_subject(SmackRuleSet handle,
					     const char *subject);

/*!
 * Remove all rules with the given object from a rule set.
 *
 * @param handle handle to a rules
 * @param object object of the rule
 */
extern void smack_rule_set_remove_by_object(SmackRuleSet handle,
					    const char *object);

/*!
 * Does the given subject have at least the given access to the given object?
 *
 * @param handle handle to a rules
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access string defining access type
 * @return boolean value
 */

extern int smack_rule_set_have_access(SmackRuleSet handle, const char *subject,
 				      const char *object, const char *access);

/*!
 * Set SMACK64 security attribute for a given file.
 *
 * @param path path to a file
 * @param attr attribute name
 * @param smack new value
 * @return 0 on success
 */
extern int smack_xattr_set_to_file(const char *path, const char *attr,
				   const char *smack);

/*!
 * Get SMACK64 security attribute for a given path.
 * Allocated memory must be freed by the caller.
 *
 * @param path path to a file
 * @param attr attribute name
 * @param smack current value
 * @return 0 on success
 */
extern int smack_xattr_get_from_file(const char *path, const char *attr,
				     char **smack);

/*!
 * Get SMACK64 security attribute for a given pid.
 *
 * @param pid pid of a process
 * @param smack current value
 * @return 0 on success
 */
extern int smack_xattr_get_from_proc(int pid, char **smack);

/*!
 * Create a new label set. The returned rule set must be freed with
 * smack_label_set_delete().
 *
 * @return handle to the rule set. Returns NULL if allocation fails.
 */
extern SmackLabelSet smack_label_set_new(void);

/*!
 * Read labels from a given file.
 *
 * @param path path to the file containing label set
 *
 * @return SmackLabelSet instance on success
 */
extern SmackLabelSet smack_label_set_new_from_file(const char *path);

/*!
 * Free resources allocated by labels.
 *
 * @param handle handle to a rules
 */
void smack_label_set_delete(SmackLabelSet handle);

/*!
 * Write labels to a given file.
 *
 * @param handle handle to label set
 * @param path path to the label set file
 * @return 0 on success
 */
extern int smack_label_set_save_to_file(SmackLabelSet handle, const char *path);


/*!
 * Add new label to a label set.
 *
 * @param handle handle to a label set
 * @param long_name long label
 * @return 0 on success
 */
extern int smack_label_set_add(SmackLabelSet handle, const char *long_name);

/*!
 * Get short label.
 *
 * @param handle handle to a label set
 * @param long_name long label
 */
extern const char *smack_label_set_to_short_name(SmackLabelSet handle,
						 const char *long_name);

/*!
 * Get long label.
 *
 * @param handle handle to a label set
 * @param short_name short_name
 */
extern const char *smack_label_set_to_long_name(SmackLabelSet handle,
						const char *short_name);



#ifdef __cplusplus
}
#endif

#endif // SMACK_H
