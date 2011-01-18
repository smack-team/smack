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

#include <sys/types.h>

/*!
 * Smack config file default paths.
 */
#define SMACK_ACCESSES_PATH "/etc/smack/accesses"
#define SMACK_LABELS_PATH "/etc/smack/labels"

/*!
 * Extended attributes.
 */
#define SMACK64 "security.SMACK64"
#define SMACK64EXEC "security.SMACK64EXEC"
#define SMACK64MMAP "security.SMACK64MMAP"

/*!
 * Handle to a in-memory representation of set of Smack rules.
 */
typedef struct _SmackRuleSet *SmackRuleSet;

/*!
 * Handle to a in-memory representation for label repository that contains
 * mapping between long and short names for labels. Short names are essentially
 * standard Smack labels.
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
 * Takes subject and object as long names and maps them to short names if the
 * parameter labels is given (not set to NULL). In this case, if short labels
 * are not found, this function fails and executes no action.
 *
 * @param path path to the file containing rules
 * @param subject read only rules for the given subject if not set to NULL.
 * @return SmackRuleSet instance on success
 */
extern SmackRuleSet smack_rule_set_new_from_file(const char *path,
						 const char *subject,
						 SmackLabelSet labels);

/*!
 * Free resources allocated by rules.
 *
 * @param handle handle to a rules
 */
extern void smack_rule_set_delete(SmackRuleSet handle);

/*!
 * Write rules to a given file. Does not write rules with no access defined.
 *
 * Takes subject and object as long names and maps them to short names if the
 * parameter labels is given (not set to NULL). In this case, if short labels
 * are not found, this function fails and executes no action.
 *
 * @param handle handle to a rules
 * @param path path to the rules file
 * @param labels handle to a label set
 * @return 0 on success
 */
extern int smack_rule_set_save_to_file(SmackRuleSet handle, const char *path,
				       SmackLabelSet labels);

/*!
 * Write rules to /smack/load. Does not write rules with no access defined.
 *
 * @param handle handle to a rule set
 * @param path path to the SmackFS load file
 * @return 0 on success
 */
extern int smack_rule_set_save_to_kernel(SmackRuleSet handle, const char *path);

/*!
 * Clear rules from kernel.
 *
 * @param handle handle to a rules
 * @param path path to the rules file
 * @return 0 on success
 */
extern int smack_rule_set_clear_from_kernel(SmackRuleSet handle, const char *path);

/*!
 * Add new rule to a rule set. Updates existing rule if there is already rule
 * for the given subject and object.
 *
 * Takes subject and object as long names and maps them to short names if the
 * parameter labels is given (not set to NULL). In this case, if short labels
 * are not found, this function fails and executes no action.
 *
 * @param handle handle to a rule set
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access access string (rwxa)
 * @param labels handle to a label set
 * @return 0 on success
 */
extern int smack_rule_set_add(SmackRuleSet handle, const char *subject,
			      const char *object, const char *access,
			      SmackLabelSet labels);

/*!
 * Remove rule from a rule set.
 *
 * Takes subject and object as long names and maps them to short names if the
 * parameter labels is given (not set to NULL). In this case, if short labels
 * are not found, this function fails and executes no action.
 *
 * @param handle handle to a rule set
 * @param subject subject of the rule
 * @param object object of the rule
 * @param labels handle to a label set
 * @return 0 on success
 */
extern void smack_rule_set_remove(SmackRuleSet handle, const char *subject,
				  const char *object, SmackLabelSet labels);

/*!
 * Remove all rules with the given subject from a rule set.
 *
 * Takes subject as long name and maps it to short name if the
 * parameter labels is given (not set to NULL). In this case,
 * if short label is not found, this function fails and executes
 * no action.
 *
 * @param handle handle to a rule set
 * @param subject subject of the rule
 * @param labels handle to a label set
 */
extern void smack_rule_set_remove_by_subject(SmackRuleSet handle,
					     const char *subject,
					     SmackLabelSet labels);

/*!
 * Remove all rules with the given object from a rule set.
 
 * Takes subject as long name and maps it to short name if the
 * parameter labels is given (not set to NULL). In this case,
 * if short label is not found, this function fails and executes
 * no action.
 *
 * @param handle handle to a rule set
 * @param object object of the rule
 * @param labels handle to a label set
 */
extern void smack_rule_set_remove_by_object(SmackRuleSet handle,
					    const char *object,
					    SmackLabelSet labels);

/*!
 * Check access to a give object.
 *
 * Takes subject and object as long names and maps them to short names if the
 * parameter labels is given (not set to NULL). In this case, if short labels
 * are not found, this function fails and executes no action.
 *
 * @param handle handle to a rule set
 * @param subject subject of the rule
 * @param object object of the rule
 * @param access string defining access type
 * @param labels handle to a label set
 * @return boolean value
 */
extern int smack_rule_set_have_access(SmackRuleSet handle, const char *subject,
 				      const char *object, const char *access,
				      SmackLabelSet labels);

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
 * Calculate eight byte short name from long name.
 *
 * @param long_name long name for the label
 * @param short_name short name of the label. Given character
 * array must have size 9 at minimum.
 */
extern void smack_label_set_get_short_name(const char *long_name,
					   char *short_name);

/*!
 * Add new label to a label set.
 *
 * @param handle handle to a label set
 * @param long_name long name for the label as input
 *
 * @return pointer to the short name is returned when the operation is
 * succesful. Otherwise, NULL is returned.
 */
extern const char *smack_label_set_add(SmackLabelSet handle,
				       const char *long_name);

/*!
 * Remove a label from a label set.
 *
 * @param handle handle to a label set
 * @param long_name long label
 */
extern void smack_label_set_remove(SmackLabelSet handle, const char *long_name);

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


/*!
 * Set SMACK64 security attribute for a given file.
 *
 * @param path path to a file
 * @param attr attribute name
 * @param smack new value
 * @param labels label set. Not used if set to NULL. Otherwise, converts
 * to short name.
 * @return 0 on success
 */
extern int smack_xattr_set_to_file(const char *path, const char *attr,
				   const char *smack, SmackLabelSet labels);

/*!
 * Get SMACK64 security attribute for a given path.
 * Allocated memory must be freed by the caller.
 *
 * @param path path to a file
 * @param attr attribute name
 * @param smack attribute value
 * @param size size of the character array reserved for the value
 * @param labels label set. Not used if set to NULL. Otherwise, converts
 * to long name.
 * @return 0 on success
 */
extern ssize_t smack_xattr_get_from_file(const char *path, const char *attr,
					 char *smack, size_t size,
					 SmackLabelSet labels);

/*!
 * Get SMACK64 security attribute for a given pid.
 *
 * @param pid pid of a process
 * @param smack attribute value
 * @param size size of the character array reserved for the value
 * @param labels label set. Not used if set to NULL. Otherwise, converts
 * to long name.
 * @return 0 on success
 */
extern ssize_t smack_xattr_get_from_proc(int pid, char *smack,
					 size_t size,
					 SmackLabelSet labels);

#ifdef __cplusplus
}
#endif

#endif // SMACK_H
