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
 * Author: Jarkko Sakkinen <ext-jarkko.2.sakkinen@nokia.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include "../src/smack.h"

START_TEST(test_save_to_kernel)
{
	int rc;
	const char *sn;
	SmackRuleSet rules;

	rules = smack_rule_set_new(NULL);
	fail_unless(rules != NULL, "Creating rule set failed");
	if (rules == NULL)
		return;

	smack_rule_set_add(rules, "Apple", "Orange", "rwx");
	smack_rule_set_add(rules, "Plum", "Peach", "rx");
	smack_rule_set_add(rules, "Banana", "Peach", "xa");

	smack_rule_set_remove(rules, "Plum", "Peach");

	rc = smack_rule_set_apply_kernel(
		rules,
		"save_to_kernel-kernel");
	fail_unless(rc == 0, "Failed to write the rule set");

	fail_unless(smack_have_access("save_to_file-rules", "Banana", "Peach", "x"),
				      "Access not granted");
	fail_unless(!smack_have_access("save_to_file-rules", "Banana", "Peach", "r"),
				       "Access not granted");
	fail_unless(!smack_have_access("save_to_file-rules", "Apple", "Orange", "a"),
				       "Access not granted");

	smack_rule_set_free(rules);
}
END_TEST

START_TEST(test_save_to_file)
{
	int rc;
	const char *sn;
	SmackRuleSet rules;

	rules = smack_rule_set_new(NULL);
	fail_unless(rules != NULL, "Creating rule set failed");
	if (rules == NULL)
		return;

	smack_rule_set_add(rules, "Apple", "Orange", "rwx");
	smack_rule_set_add(rules, "Plum", "Peach", "rx");
	smack_rule_set_add(rules, "Banana", "Peach", "xa");

	smack_rule_set_remove(rules, "Plum", "Peach");

	rc = smack_rule_set_save(
		rules,
		"save_to_file-rules");
	fail_unless(rc == 0, "Failed to write the rule set");

	fail_unless(smack_have_access("save_to_file-rules", "Banana", "Peach", "x"),
				      "Access not granted");
	fail_unless(!smack_have_access("save_to_file-rules", "Banana", "Peach", "r"),
				       "Access not granted");
	fail_unless(!smack_have_access("save_to_file-rules", "Apple", "Orange", "a"),
				       "Access not granted");

	smack_rule_set_free(rules);
}
END_TEST

START_TEST(test_rule_set_remove_by_subject)
{
	int rc;
	SmackRuleSet rules;

	rules = smack_rule_set_new(NULL);
	fail_unless(rules != NULL, "Creating rule set failed");
	if (rules == NULL)
		return;

	smack_rule_set_add(rules, "Apple", "Orange", "rwx");
	smack_rule_set_add(rules, "Plum", "Peach", "rx");
	smack_rule_set_add(rules, "Banana", "Peach", "xa");

	smack_rule_set_remove_by_subject(rules, "Plum");

	rc = smack_rule_set_have_access(rules, "Plum", "Peach", "rx");
	fail_unless(rc == 0, "Access granted to a removed rule");

	smack_rule_set_free(rules);
}
END_TEST

START_TEST(test_rule_set_remove_by_object)
{
	int rc;
	SmackRuleSet rules;

	rules = smack_rule_set_new(NULL);
	fail_unless(rules != NULL, "Creating rule set failed");
	if (rules == NULL)
		return;

	smack_rule_set_add(rules, "Apple", "Orange", "rwx");
	smack_rule_set_add(rules, "Plum", "Peach", "rx");
	smack_rule_set_add(rules, "Banana", "Peach", "xa");

	smack_rule_set_remove_by_object(rules, "Peach");

	rc = smack_rule_set_have_access(rules, "Plum", "Peach", "rx");
	fail_unless(rc == 0, "Access granted to a removed rule");

	smack_rule_set_free(rules);
}
END_TEST

Suite *ruleset_suite (void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Rules");

	tc_core = tcase_create("Rules");
	tcase_add_test(tc_core, test_save_to_kernel);
	tcase_add_test(tc_core, test_save_to_file);
	tcase_add_test(tc_core, test_rule_set_remove_by_subject);
	tcase_add_test(tc_core, test_rule_set_remove_by_object);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int nfailed;
	Suite *s = ruleset_suite();
	SRunner *sr = srunner_create(s);
	srunner_set_log(sr, "check_rules.log");
	srunner_run_all(sr, CK_ENV);
	nfailed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (nfailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

