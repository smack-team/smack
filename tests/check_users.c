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

START_TEST(test_rw_users)
{
	int rc;
	smack_users_t users = smack_create_users();
	fail_unless(users != NULL, "Users creation failed");
	rc = smack_read_users_from_file(users, "data/rw_users-in.txt");
	fail_unless(rc == 0, "Failed to read users");
	rc = smack_write_users_to_file(users, "rw_users-result.txt");
	fail_unless(rc == 0, "Failed to write ruleset");
	rc = files_equal("rw_users-result.txt", "data/rw_users-excepted.txt");
	fail_unless(rc == 1, "Unexcepted result");
	smack_destroy_users(users);
}
END_TEST

START_TEST(test_user_label)
{
	int rc;
	const char *l;

	smack_users_t users = smack_create_users();
	fail_unless(users != NULL, "Users creation failed");

	rc = smack_read_users_from_file(users, "data/rw_users-in.txt");
	fail_unless(rc == 0, "Failed to read users");

	l = smack_get_user_label(users, "bar");
	fail_unless(l != NULL, "Label not found");
	fail_unless(strcmp(l, "Orange") == 0, "Unexcepted label %s", l);

	smack_destroy_users(users);
}
END_TEST

Suite *ruleset_suite (void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("User");

	tc_core = tcase_create("Users");
	tcase_add_test(tc_core, test_rw_users);
	tcase_add_test(tc_core, test_user_label);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int nfailed;
	Suite *s = ruleset_suite();
	SRunner *sr = srunner_create(s);
	srunner_set_log(sr, "check_users.log");
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

