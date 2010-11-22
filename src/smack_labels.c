#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uthash.h>
#include "smack.h"

#define SMACK64_LEN 23
struct smack_label {
	char *long_name;
	char *short_name;
	UT_hash_handle long_name_hh;
	UT_hash_handle short_name_hh;
};

struct _SmackLabelSet {
	struct smack_label *label_by_long_name;
	struct smack_label *label_by_short_name;
};

static int add_label(struct smack_label **label_by_long_name,
		     struct smack_label **label_by_short_name,
		     const char *long_name,
		     const char *short_name);

SmackLabelSet smack_label_set_new(void)
{
	struct _SmackLabelSet *result =
		calloc(1, sizeof(struct _SmackLabelSet));
	return result;
}

extern SmackLabelSet smack_label_set_new_from_file(const char *path)
{
	SmackLabelSet labels;
	FILE *file;
	char *buf = NULL;
	const char *ll, *sl;
	size_t size;
	int ret = 0;

	file = fopen(path, "r");
	if (file == NULL)
		return NULL;

	labels = smack_label_set_new();
	if (labels == NULL) {
		fclose(file);
		return NULL;
	}

	while (ret == 0 && getline(&buf, &size, file) != -1) {
		ll = strtok(buf, " \t\n");
		sl = strtok(NULL, " \t\n");

		if (ll == NULL || sl == NULL || strtok(NULL, " \t\n") != NULL) {
			ret = -1;
		} else {
			ret = add_label(&labels->label_by_long_name, &labels->label_by_short_name,
					ll, sl);
		}

		free(buf);
		buf = NULL;
	}

	if (ret != 0 || ferror(file)) {
		smack_label_set_delete(labels);
		labels = NULL;
	}

	free(buf);
	fclose(file);
	return labels;
}

void smack_label_set_delete(SmackLabelSet handle)
{
	struct smack_label *l, *tmp;

	HASH_ITER(long_name_hh, handle->label_by_long_name, l, tmp) {
		HASH_DELETE(long_name_hh, handle->label_by_long_name, l);
		HASH_DELETE(short_name_hh, handle->label_by_short_name, l);
		free(l->long_name);
		free(l->short_name);
		free(l);
	}
}

int smack_label_set_save_to_file(SmackLabelSet handle, const char *path)
{
	struct smack_label *s, *stmp;
	FILE *file;
	int err = 0;

	file = fopen(path, "w+");
	if (!file)
		return -1;

	HASH_ITER(long_name_hh, handle->label_by_long_name, s, stmp) {
		err = fprintf(file, "%s %s\n",
			      s->long_name, s->short_name);

		if (err < 0) {
			fclose(file);
			return errno;
		}
	}

	fclose(file);
	return 0;
}

int smack_label_set_add(SmackLabelSet handle, const char *long_name)
{
	char sl[SMACK64_LEN + 1];
	int pos, len ,ret;

	if (long_name == NULL || strlen(long_name) == 0)
		return -EPERM;

	len = strlen(long_name);
	pos = (len > SMACK64_LEN) ? len - SMACK64_LEN : 0;

	strcpy(sl, &long_name[pos]);

	ret = add_label(&handle->label_by_long_name, &handle->label_by_short_name,
			long_name, sl);

	return ret == 0 ? 0  : -1;
}

const char *smack_label_set_to_short_name(SmackLabelSet handle,
 					   const char *long_name)
{
	struct smack_label *l;
	HASH_FIND(long_name_hh, handle->label_by_long_name, long_name, strlen(long_name), l);
	return l->short_name;
}

const char *smack_label_set_to_long_name(SmackLabelSet handle,
					  const char *short_name)
{
	struct smack_label *l;
	HASH_FIND(short_name_hh, handle->label_by_short_name, short_name, strlen(short_name), l);
	return l->long_name;
}

static int add_label(struct smack_label **label_by_long_name,
		     struct smack_label **label_by_short_name,
		     const char *long_name,
		     const char *short_name)
{
	struct smack_label *l;

	if (strlen(short_name) > SMACK64_LEN)
		return -ERANGE;

	HASH_FIND(long_name_hh, *label_by_long_name, long_name,
		  strlen(long_name), l);
	if (l != NULL)
		return -EEXIST;

	HASH_FIND(short_name_hh, *label_by_short_name, short_name,
		  strlen(short_name), l);
	if (l != NULL)
		return -EEXIST;

	l = calloc(1, sizeof(struct smack_label));
	if (l == NULL)
		return -ENOMEM;

	l->long_name = strdup(long_name);
	l->short_name = strdup(short_name);

	if (l->long_name == NULL || l->short_name == NULL) {
		free(l->long_name);
		free(l->short_name);
		free(l);
		return -ENOMEM;
	}

	HASH_ADD_KEYPTR(long_name_hh, *label_by_long_name, l->long_name, strlen(l->long_name), l);
	HASH_ADD_KEYPTR(short_name_hh, *label_by_short_name, l->short_name, strlen(l->short_name), l);

	return 0;
}

