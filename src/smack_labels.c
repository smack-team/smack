#include <stdio.h>
#include "smack.h"

SmackLabelSet *smack_label_set_new(void)
{
    return NULL;
}

extern SmackLabelSet smack_label_set_new_from_file(const char *path,
						   const char *subject)
{
	return NULL;
}


void smack_label_set_delete(SmackLabelSet *handle)
{
}


int smack_label_set_add(SmackLabelSet handle, const char *long_label)
{
	return 0;
}


const char *smack_label_set_to_short_label(SmackLabelSet handle,
 					   const char *long_label)
{
	return NULL;
}

const char *smack_label_set_to_long_label(SmackLabelSet handle,
					  const char *short_label)
{
	return NULL;
}

