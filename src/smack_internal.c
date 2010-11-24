#include <string.h>
#include "smack_internal.h"

#define KNOWN_LABELS_COUNT 4

static const char *known_labels[] = { "_", "^", "*", "@" };

const char *get_known_label(const char *label)
{
	int i;

	for (i = 0; i < KNOWN_LABELS_COUNT; i++)
		if (strcmp(label, known_labels[i]) == 0)
			return known_labels[i];

	return NULL;
}

