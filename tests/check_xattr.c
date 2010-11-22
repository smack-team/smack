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

START_TEST(test_set_smack_to_file)
{
	FILE *file;
	int rc = 0;
	char *smack = NULL;

	file = fopen("set_smack-dummy.txt", "w");
	fprintf(file, "dummy\n");
	fclose(file);

	rc = smack_xattr_set_to_file("set_smack-dummy.txt", SMACK64, "Apple");
	fail_unless(rc == 0, "Failed to set SMACK64");

	rc = smack_xattr_get_from_file("set_smack-dummy.txt", SMACK64, &smack);
	fail_unless(rc == 0, "Failed to get SMACK64");

	rc = strcmp(smack, "Apple");
	fail_unless(rc == 0, "smack %s not equal to Apple", smack);

	free(smack);
}
END_TEST

START_TEST(test_set_smackexec_to_file)
{
	FILE *file;
	int rc;
	char *smack = NULL;

	file = fopen("set_smack-dummy.txt", "w");
	fprintf(file, "dummy\n");
	fclose(file);

	rc = smack_xattr_set_to_file("set_smack-dummy.txt", SMACK64EXEC, "Apple");
	fail_unless(rc == 0, "Failed to set SMACK64EXEC");

	rc = smack_xattr_get_from_file("set_smack-dummy.txt", SMACK64EXEC, &smack);
	fail_unless(rc == 0, "Failed to get SMACK64EXEC");

	rc = strcmp(smack, "Apple");
	fail_unless(rc == 0, "smack %s not equal to Apple", smack);

	free(smack);
}
END_TEST

Suite *ruleset_suite (void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Xattr");

	tc_core = tcase_create("Xattr");
	tcase_add_test(tc_core, test_set_smack_to_file);
	tcase_add_test(tc_core, test_set_smackexec_to_file);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int nfailed;
	Suite *s = ruleset_suite();
	SRunner *sr = srunner_create(s);
	srunner_set_log(sr, "check_xattr.log");
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

