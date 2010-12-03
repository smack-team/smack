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

#define LONG_LABEL_1 "FooFooFooFooFooFooFooFooFooFooFooFooFoo"
#define LONG_LABEL_2 "BarBarBarBarBarBarBarBarBarBarBarBarBar"

static int files_equal(const char *filename1, const char *filename2);

START_TEST(test_rule_set_read_from_file_and_save_to_kernel)
{
	int rc;
	const char *sn;
	SmackLabelSet labels;
	SmackRuleSet rules;

	labels = smack_label_set_new();
	fail_unless(labels != NULL, "Creating label set failed");

	sn = smack_label_set_add(labels, LONG_LABEL_1);
	fail_unless(sn != NULL, "Adding label was not succesful");

	sn = smack_label_set_add(labels, LONG_LABEL_2);
	fail_unless(sn != NULL, "Adding label was not succesful");

	rules = smack_rule_set_new_from_file(
		"data/rule_set_read_from_file_and_save_to_kernel-in.txt", NULL, labels);
	fail_unless(rules != NULL, "Reading rules failed");

	if (rules == NULL)
		return;

	rc = smack_rule_set_save_to_file(rules,
		"rule_set_read_from_file_and_save_to_kernel-result.txt",
		NULL);
	fail_unless(rc == 0, "Failed to write ruleset");

	rc = files_equal(
		"rule_set_read_from_file_and_save_to_kernel-result.txt",
		"data/rule_set_read_from_file_and_save_to_kernel-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");

	smack_rule_set_delete(rules);
	smack_label_set_delete(labels);
}
END_TEST

START_TEST(test_rule_set_add_and_save_to_file)
{
	int rc;
	const char *sn;

	SmackRuleSet rules = smack_rule_set_new();
	fail_unless(rules != NULL, "Creating rule set failed");

	SmackLabelSet labels = smack_label_set_new();
	fail_unless(labels != NULL, "Creating label set failed");

	sn = smack_label_set_add(labels, LONG_LABEL_1);
	fail_unless(sn != NULL, "Adding label was not succesful");

	sn = smack_label_set_add(labels, LONG_LABEL_2);
	fail_unless(sn != NULL, "Adding label was not succesful");

	rc = smack_rule_set_add(rules, LONG_LABEL_1, LONG_LABEL_2, "rx", labels);
	fail_unless(rc == 0, "Adding rule was not succesful");

	rc = smack_rule_set_add(rules, LONG_LABEL_2, LONG_LABEL_1, "rwa", labels);
	fail_unless(rc == 0, "Adding rule was not succesful");

	rc = smack_rule_set_save_to_file(rules,
		"rule_set_add_and_save_to_config-result.txt",
		labels);
	fail_unless(rc == 0, "Failed to write ruleset");

	rc = files_equal(
		"rule_set_add_and_save_to_config-result.txt",
		"data/rule_set_add_and_save_to_config-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");

	smack_rule_set_delete(rules);
	smack_label_set_delete(labels);
}
END_TEST

START_TEST(test_rule_set_remove_and_save_to_kernel)
{
	int rc;
	SmackRuleSet rules;

	rules = smack_rule_set_new_from_file(
		"data/rule_set_remove_and_save_to_kernel-in.txt", NULL, NULL);
	fail_unless(rules != NULL, "Reading rules failed");

	smack_rule_set_remove(rules, "Orange", "Apple", NULL);

	rc = smack_rule_set_save_to_kernel(rules,
		"rule_set_remove_and_save_to_kernel-result.txt");
	fail_unless(rc == 0, "Failed to write ruleset");

	rc = files_equal(
		"rule_set_remove_and_save_to_kernel-result.txt",
		"data/rule_set_remove_and_save_to_kernel-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");

	smack_rule_set_delete(rules);
}
END_TEST

START_TEST(test_rule_set_remove_by_subject_and_save_to_kernel)
{
	int rc;
	SmackRuleSet rules;
	
	rules = smack_rule_set_new_from_file(
		"data/rule_set_remove_by_subject_and_save_to_kernel-in.txt",
		NULL, NULL);
	fail_unless(rules != NULL, "Reading rules failed");

	smack_rule_set_remove_by_subject(rules, "Foo", NULL);

	rc = smack_rule_set_save_to_kernel(rules, 
		"rule_set_remove_by_subject_and_save_to_kernel-result.txt");
	fail_unless(rc == 0, "Failed to write ruleset");

	rc = files_equal(
		"rule_set_remove_by_subject_and_save_to_kernel-result.txt",
		 "data/rule_set_remove_by_subject_and_save_to_kernel-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");

	smack_rule_set_delete(rules);
}
END_TEST

START_TEST(test_rule_set_remove_by_object_and_save_to_kernel)
{
	int rc;
	SmackRuleSet rules;

	rules = smack_rule_set_new_from_file(
		"data/rule_set_remove_by_object_and_save_to_kernel-in.txt",
		NULL, NULL);
	fail_unless(rules != NULL, "Reading rules failed");

	smack_rule_set_remove_by_object(rules, "Apple", NULL);

	rc = smack_rule_set_save_to_kernel(rules,
		"rule_set_remove_by_object_and_save_to_kernel-result.txt");
	fail_unless(rc == 0, "Failed to write ruleset");

	rc = files_equal(
		"rule_set_remove_by_object_and_save_to_kernel-result.txt",
		 "data/rule_set_remove_by_object_and_save_to_kernel-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");

	smack_rule_set_delete(rules);
}
END_TEST

START_TEST(test_rule_set_add_remove_long)
{
	int rc;
	const char *sn;

	SmackRuleSet rules = smack_rule_set_new();
	fail_unless(rules != NULL, "Creating rule set failed");

	SmackLabelSet labels = smack_label_set_new();
	fail_unless(labels != NULL, "Creating label set failed");

	sn = smack_label_set_add(labels, LONG_LABEL_1);
	fail_unless(sn != NULL, "Adding label was not succesful");

	sn = smack_label_set_add(labels, LONG_LABEL_2);
	fail_unless(sn != NULL, "Adding label was not succesful");

	rc = smack_rule_set_add(rules, LONG_LABEL_1, LONG_LABEL_2, "rx", labels);
	fail_unless(rc == 0, "Adding rule was not succesful");

	rc = smack_rule_set_add(rules, LONG_LABEL_2, LONG_LABEL_1, "rwa", labels);
	fail_unless(rc == 0, "Adding rule was not succesful");

	smack_rule_set_remove(rules, LONG_LABEL_1, LONG_LABEL_2, labels);

	rc = smack_rule_set_have_access(rules, LONG_LABEL_2, LONG_LABEL_1, "a", labels);
	fail_unless(rc, "Access failure");

	rc = smack_rule_set_have_access(rules, LONG_LABEL_1, LONG_LABEL_2, "r", labels);
	fail_unless(!rc, "Access failure");

	smack_rule_set_delete(rules);
	smack_label_set_delete(labels);
}
END_TEST

START_TEST(test_rule_set_add_long_no_labels)
{
	int rc;

	SmackRuleSet rules = smack_rule_set_new();
	fail_unless(rules != NULL, "Creating rule set failed");

	SmackLabelSet labels = smack_label_set_new();
	fail_unless(labels != NULL, "Creating label set failed");

	rc = smack_rule_set_add(rules, LONG_LABEL_1, LONG_LABEL_2, "rx", labels);
	fail_unless(rc != 0, "Adding rule was succesful");

	smack_rule_set_delete(rules);
	smack_label_set_delete(labels);
}
END_TEST

Suite *ruleset_suite (void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Rules");

	tc_core = tcase_create("Rules");
	tcase_add_test(tc_core, test_rule_set_read_from_file_and_save_to_kernel);
	tcase_add_test(tc_core, test_rule_set_add_and_save_to_file);
	tcase_add_test(tc_core, test_rule_set_remove_and_save_to_kernel);
	tcase_add_test(tc_core, test_rule_set_remove_by_subject_and_save_to_kernel);
	tcase_add_test(tc_core, test_rule_set_remove_by_object_and_save_to_kernel);
	tcase_add_test(tc_core, test_rule_set_add_remove_long);
	tcase_add_test(tc_core, test_rule_set_add_long_no_labels);
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

