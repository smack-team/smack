#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uthash.h>
#include "smack.h"
#include "smack_internal.h"

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

static struct smack_label *add_label(struct smack_label **label_by_long_name,
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
	struct smack_label *l;
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

		if (ll == NULL || sl == NULL ||
		    strtok(NULL, " \t\n") != NULL ||
		    strlen(sl) > SMACK64_LEN) {
			ret = -1;
		    break;
		}

		l = add_label(&labels->label_by_long_name,
			      &labels->label_by_short_name,
			      ll, sl);
		if (l == NULL) {
			ret = -1;
			break;
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

	if (handle == NULL)
		return;

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

void smack_label_set_get_short_name(const char *long_name,
				    char *short_name)
{
	uint32_t h;
	int i, c;

	// djb2 based on http://www.cse.yorku.ca/~oz/hash.html
	h = 5381;

	for (i = 0; long_name[i] != '\0'; i++) {
		c = long_name[i];
		h = ((h << 5) + h) + c;
	}

	sprintf(short_name, "%08X", h);
}

const char *smack_label_set_add(SmackLabelSet handle, const char *long_name)
{
	char short_name[SMACK64_LEN + 1];
	struct smack_label *l;

	smack_label_set_get_short_name(long_name, short_name);

	l  = add_label(&handle->label_by_long_name,
		       &handle->label_by_short_name,
		       long_name, short_name);

	return l != NULL ? l->short_name : NULL;
}

void smack_label_set_remove(SmackLabelSet handle, const char *long_name)
{
	struct smack_label *l;

	HASH_FIND(long_name_hh, handle->label_by_long_name, long_name, strlen(long_name), l);

	if (l == NULL)
		return;

	HASH_DELETE(long_name_hh, handle->label_by_long_name, l);
	HASH_DELETE(short_name_hh, handle->label_by_short_name, l);
	free(l->long_name);
	free(l->short_name);
	free(l);
}

const char *smack_label_set_to_short_name(SmackLabelSet handle,
					  const char *long_name)
{
	struct smack_label *l;
	const char *res;

	HASH_FIND(long_name_hh, handle->label_by_long_name, long_name, strlen(long_name), l);

	if (l == NULL)
		return NULL;

	return l->short_name;
}

const char *smack_label_set_to_long_name(SmackLabelSet handle,
					 const char *short_name)
{
	struct smack_label *l;
	const char *res;

	HASH_FIND(short_name_hh, handle->label_by_short_name, short_name, strlen(short_name), l);

	if (l == NULL)
		return NULL;

	return l->long_name;
}

static struct smack_label *add_label(struct smack_label **label_by_long_name,
				     struct smack_label **label_by_short_name,
				     const char *long_name,
				     const char *short_name)
{
	struct smack_label *l;

	HASH_FIND(long_name_hh, *label_by_long_name, long_name,
		  strlen(long_name), l);
	if (l != NULL)
		return NULL;

	HASH_FIND(short_name_hh, *label_by_short_name, short_name,
		  strlen(short_name), l);
	if (l != NULL)
		return NULL;

	l = calloc(1, sizeof(struct smack_label));
	if (l == NULL)
		return NULL;

	l->long_name = strdup(long_name);
	l->short_name = strdup(short_name);

	if (l->long_name == NULL || l->short_name == NULL) {
		free(l->long_name);
		free(l->short_name);
		free(l);
		return NULL;
	}

	HASH_ADD_KEYPTR(long_name_hh, *label_by_long_name, l->long_name, strlen(l->long_name), l);
	HASH_ADD_KEYPTR(short_name_hh, *label_by_short_name, l->short_name, strlen(l->short_name), l);

	return l;
}

