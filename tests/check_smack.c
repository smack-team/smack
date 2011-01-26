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

static int files_equal(const char *filename1, const char *filename2);

START_TEST(test_save_to_kernel)
{
	int rc;
	const char *sn;
	SmackRuleSet rules;

	rules = smack_rule_set_new(NULL, NULL);
	fail_unless(rules != NULL, "Creating rule set failed");
	if (rules == NULL)
		return;

	smack_rule_set_add(rules, "Apple", "Orange", "rwx");
	smack_rule_set_add(rules, "Plum", "Peach", "rx");
	smack_rule_set_add(rules, "Banana", "Peach", "xa");

	smack_rule_set_remove(rules, "Plum", "Peach");

	rc = smack_rule_set_save_kernel(
		rules,
		"test_save_to_kernel-result.txt");
	fail_unless(rc == 0, "Failed to write the rule set");

	rc = files_equal(
		"test_save_to_kernel-result.txt",
		"data/test_save_to_kernel-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");

	smack_rule_set_delete(rules);
}
END_TEST

START_TEST(test_save_to_file)
{
	int rc;
	const char *sn;
	SmackRuleSet rules;

	rules = smack_rule_set_new(NULL, NULL);
	fail_unless(rules != NULL, "Creating rule set failed");
	if (rules == NULL)
		return;

	smack_rule_set_add(rules, "Apple", "Orange", "rwx");
	smack_rule_set_add(rules, "Plum", "Peach", "rx");
	smack_rule_set_add(rules, "Banana", "Peach", "xa");

	smack_rule_set_remove(rules, "Plum", "Peach");

	rc = smack_rule_set_save_config(
		rules,
		"test_save_to_file-result.txt");
	fail_unless(rc == 0, "Failed to write the rule set");

	rc = files_equal(
		"test_save_to_file-result.txt",
		"data/test_save_to_file-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");

	smack_rule_set_delete(rules);
}
END_TEST

START_TEST(test_rule_set_remove_by_subject)
{
	int rc;
	SmackRuleSet rules;

	rules = smack_rule_set_new(NULL, NULL);
	fail_unless(rules != NULL, "Creating rule set failed");
	if (rules == NULL)
		return;

	smack_rule_set_add(rules, "Apple", "Orange", "rwx");
	smack_rule_set_add(rules, "Plum", "Peach", "rx");
	smack_rule_set_add(rules, "Banana", "Peach", "xa");

	smack_rule_set_remove_by_subject(rules, "Plum");

	rc = smack_rule_set_have_access(rules, "Plum", "Peach", "rx");
	fail_unless(rc == 0, "Access granted to a removed rule");

	smack_rule_set_delete(rules);
}
END_TEST

START_TEST(test_rule_set_remove_by_object)
{
	int rc;
	SmackRuleSet rules;

	rules = smack_rule_set_new(NULL, NULL);
	fail_unless(rules != NULL, "Creating rule set failed");
	if (rules == NULL)
		return;

	smack_rule_set_add(rules, "Apple", "Orange", "rwx");
	smack_rule_set_add(rules, "Plum", "Peach", "rx");
	smack_rule_set_add(rules, "Banana", "Peach", "xa");

	smack_rule_set_remove_by_object(rules, "Peach");

	rc = smack_rule_set_have_access(rules, "Plum", "Peach", "rx");
	fail_unless(rc == 0, "Access granted to a removed rule");

	smack_rule_set_delete(rules);
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

static int files_equal(const char *filename1, const char *filename2)
{
	FILE *fp1 = NULL;
	FILE *fp2 = NULL;
	char ch1, ch2;
	int rc = 0;

	fp1 = fopen(filename1, "rb");
	if (fp1 == NULL) {
		goto out;
	}

	fp2 = fopen(filename2, "rb");
	if (fp2 == NULL) {
		goto out;
	}

	rc = 1;
	for (;;) {
		if (feof(fp1) && feof(fp2))
			break;

		if (feof(fp1) || feof(fp2)) {
			rc = 0;
			break;
		}

		ch1 = fgetc(fp1);
		if (ferror(fp1)) {
			rc = 0;
			break;
		}

		ch2 = fgetc(fp2);
		if (ferror(fp2)) {
			rc = 0;
			break;
		}

		if (ch1 != ch2) {
			rc = 0;
			break;
		}
	}
out:
	if (fp1 != NULL)
		fclose(fp1);
	if (fp2 != NULL)
		fclose(fp2);
	return rc;
}

