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

START_TEST(test_add_new_rule)
{
	int rc;
	smack_rules_t rules = smack_create_rules();
	fail_unless(rules != NULL, "Ruleset creation failed");
	rc = smack_read_rules_from_file(rules, "data/add_new_rule-in.txt", NULL);
	fail_unless(rc == 0, "Failed to read ruleset");
	rc = smack_add_rule(rules, "Orange", "Apple", "ra");
	fail_unless(rc == 0, "Failed to add rule");
	rc = smack_write_rules_to_file(rules, "add_new_rule-result.txt", SMACK_FORMAT_KERNEL);
	fail_unless(rc == 0, "Failed to write ruleset");
	rc = files_equal("add_new_rule-result.txt", "data/add_new_rule-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");
	smack_destroy_rules(rules);
}
END_TEST

START_TEST(test_modify_existing_rule)
{
	int rc;
	smack_rules_t rules = smack_create_rules();
	fail_unless(rules != NULL, "Ruleset creation failed");
	rc = smack_read_rules_from_file(rules, "data/modify_existing_rule-in.txt", NULL);
	fail_unless(rc == 0, "Failed to read ruleset");
	rc = smack_add_rule(rules, "Foo", "Bar", "wx");
	fail_unless(rc == 0, "Failed to add rule");
	rc = smack_write_rules_to_file(rules, "modify_existing_rule-result.txt", SMACK_FORMAT_KERNEL);
	fail_unless(rc == 0, "Failed to write ruleset");
	rc = files_equal("modify_existing_rule-result.txt", "data/modify_existing_rule-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");
	smack_destroy_rules(rules);
}
END_TEST

START_TEST(test_rw_rules_config)
{
	int rc;
	smack_rules_t rules = smack_create_rules();
	fail_unless(rules != NULL, "Ruleset creation failed");
	rc = smack_read_rules_from_file(rules, "data/write_rules_config-excepted.txt", NULL);
	fail_unless(rc == 0, "Failed to read ruleset");
	rc = smack_write_rules_to_file(rules, "write_rules_config-result.txt", SMACK_FORMAT_CONFIG);
	fail_unless(rc == 0, "Failed to write ruleset");
	rc = files_equal("write_rules_config-result.txt", "data/write_rules_config-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");
	smack_destroy_rules(rules);
}
END_TEST

START_TEST(test_rw_rules_kernel)
{
	int rc;
	smack_rules_t rules = smack_create_rules();
	fail_unless(rules != NULL, "Ruleset creation failed");
	rc = smack_read_rules_from_file(rules, "data/write_rules_config-excepted.txt", NULL);
	fail_unless(rc == 0, "Failed to read ruleset");
	rc = smack_write_rules_to_file(rules, "write_rules_kernel-result.txt", SMACK_FORMAT_KERNEL);
	fail_unless(rc == 0, "Failed to write ruleset");
	rc = files_equal("write_rules_kernel-result.txt", "data/write_rules_kernel-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");
	smack_destroy_rules(rules);
}
END_TEST

START_TEST(test_remove_rule)
{
	int rc;
	smack_rules_t rules = smack_create_rules();
	fail_unless(rules != NULL, "Ruleset creation failed");
	rc = smack_read_rules_from_file(rules, "data/remove_rule-in.txt", NULL);
	fail_unless(rc == 0, "Failed to read ruleset");
	smack_remove_rule(rules, "Orange", "Apple");
	rc = smack_write_rules_to_file(rules, "remove_rule-result.txt", SMACK_FORMAT_KERNEL);
	fail_unless(rc == 0, "Failed to write ruleset");
	rc = files_equal("remove_rule-result.txt", "data/remove_rule-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");
	smack_destroy_rules(rules);
}
END_TEST

START_TEST(test_remove_rules_by_subject)
{
	int rc;
	smack_rules_t rules = smack_create_rules();
	fail_unless(rules != NULL, "Ruleset creation failed");
	rc = smack_read_rules_from_file(rules, "data/remove_rules_by_subject-in.txt", NULL);
	fail_unless(rc == 0, "Failed to read ruleset");
	smack_remove_rules_by_subject(rules, "Foo");
	rc = smack_write_rules_to_file(rules, "remove_rules_by_subject-result.txt", SMACK_FORMAT_KERNEL);
	fail_unless(rc == 0, "Failed to write ruleset");
	rc = files_equal("remove_rules_by_subject-result.txt", "data/remove_rules_by_subject-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");
	smack_destroy_rules(rules);
}
END_TEST

START_TEST(test_remove_rules_by_object)
{
	int rc;
	smack_rules_t rules = smack_create_rules();
	fail_unless(rules != NULL, "Ruleset creation failed");
	rc = smack_read_rules_from_file(rules, "data/remove_rules_by_object-in.txt", NULL);
	fail_unless(rc == 0, "Failed to read ruleset");
	smack_remove_rules_by_object(rules, "Apple");
	rc = smack_write_rules_to_file(rules, "remove_rules_by_object-result.txt", SMACK_FORMAT_KERNEL);
	fail_unless(rc == 0, "Failed to write ruleset");
	rc = files_equal("remove_rules_by_object-result.txt", "data/remove_rules_by_object-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");
	smack_destroy_rules(rules);
}
END_TEST

START_TEST(test_have_access_rule)
{
	int rc;
	smack_rules_t rules = smack_create_rules();
	fail_unless(rules != NULL, "Ruleset creation failed");
	rc = smack_read_rules_from_file(rules, "data/have_access_rule-in.txt", "Orange");
	fail_unless(rc == 0, "Failed to read ruleset");
	rc = smack_have_access_rule(rules, "Orange", "Apple", "a");
	fail_unless(rc, "Have access \"a\" failed");
	smack_destroy_rules(rules);
}
END_TEST

START_TEST(test_have_access_removed_rule)
{
	int rc;
	smack_rules_t rules = smack_create_rules();
	fail_unless(rules != NULL, "Ruleset creation failed");
	rc = smack_read_rules_from_file(rules, "data/have_access_rule-in.txt", "Orange");
	fail_unless(rc == 0, "Failed to read ruleset");
	smack_remove_rule(rules, "Orange", "Apple");
	rc = smack_have_access_rule(rules, "Orange", "Apple", "a");
	fail_unless(!rc, "Has access to a removed rule");
	smack_destroy_rules(rules);
}
END_TEST

Suite *ruleset_suite (void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Rules");

	tc_core = tcase_create("Rules");
	tcase_add_test(tc_core, test_add_new_rule);
	tcase_add_test(tc_core, test_modify_existing_rule);
	tcase_add_test(tc_core, test_rw_rules_config);
	tcase_add_test(tc_core, test_rw_rules_kernel);
	tcase_add_test(tc_core, test_remove_rule);
	tcase_add_test(tc_core, test_remove_rules_by_subject);
	tcase_add_test(tc_core, test_remove_rules_by_object);
	tcase_add_test(tc_core, test_have_access_rule);
	tcase_add_test(tc_core, test_have_access_removed_rule);
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

