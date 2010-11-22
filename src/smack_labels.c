#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uthash.h>
#include "smack.h"

#define SMACK64_LEN 23
struct smack_label {
	char *long_label;
	char *short_label;
	UT_hash_handle long_hh;
	UT_hash_handle short_hh;
};

struct _SmackLabelSet {
	struct smack_label *labels;
};

static int add_label(struct smack_label **labels,
		     const char *long_label,
		     const char *short_label);

SmackLabelSet smack_label_set_new(void)
{
	struct _SmackLabelSet *result =
		calloc(1, sizeof(struct _SmackLabelSet));
	return result;
}

extern SmackLabelSet smack_label_set_new_from_file(const char *path,
						   const char *subject)
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
			ret = add_label(&labels->labels, ll, sl);
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

	HASH_ITER(long_hh, handle->labels, l, tmp) {
		HASH_DELETE(long_hh, handle->labels, l);
		HASH_DELETE(short_hh, handle->labels, l);
		free(l->long_label);
		free(l->short_label);
		free(l);
	}
}

int smack_label_set_add(SmackLabelSet handle, const char *long_label)
{
	char sl[SMACK64_LEN + 1];
	int pos, len ,ret;

	if (long_label == NULL || strlen(long_label) == 0)
		return -EPERM;

	len = strlen(long_label);
	pos = (len > SMACK64_LEN) ? len - SMACK64_LEN : 0;

	strcpy(sl, &long_label[pos]);

	ret = add_label(&handle->labels, long_label, sl);

	return ret == 0 ? 0  : -1;
}

const char *smack_label_set_to_short_label(SmackLabelSet handle,
 					   const char *long_label)
{
	struct smack_label *l;
	HASH_FIND(long_hh, handle->labels, long_label, strlen(long_label), l);
	return l->short_label;
}

const char *smack_label_set_to_long_label(SmackLabelSet handle,
					  const char *short_label)
{
	struct smack_label *l;
	HASH_FIND(short_hh, handle->labels, short_label, strlen(short_label), l);
	return l->long_label;
}

static int add_label(struct smack_label **labels,
		     const char *long_label,
		     const char *short_label)
{
	struct smack_label *l;

	if (strlen(short_label) > SMACK64_LEN)
		return -ERANGE;

	HASH_FIND(long_hh, *labels, long_label, strlen(long_label), l);
	if (l != NULL)
		return -EEXIST;

	HASH_FIND(short_hh, *labels, short_label, strlen(short_label), l);
	if (l != NULL)
		return -EEXIST;

	l = calloc(1, sizeof(struct smack_label));
	if (l == NULL)
		return -ENOMEM;

	l->long_label = strdup(long_label);
	l->short_label = strdup(short_label);

	if (l->long_label == NULL || l->short_label == NULL) {
		free(l->long_label);
		free(l->short_label);
		free(l);
		return -ENOMEM;
	}

	HASH_ADD_KEYPTR(long_hh, *labels, l->long_label, strlen(l->long_label), l);
	HASH_ADD_KEYPTR(short_hh, *labels, l->short_label, strlen(l->short_label), l);

	return 0;
}

