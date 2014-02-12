#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct label {
	char *label;
	int counter;
	char *rules;
};

int r(int count)
{
	return random() % count;
}

int count_set_bits(int n)
{
	int result = 0;
	while (n) {
		result += n & 1;
		n >>= 1;
	}
	return result;
}

int random_code(int ref)
{
	int nb = 6 - count_set_bits(ref);
	int b = r(1 << nb);
	int iter = 1;
	int result = 0;
	while (nb) {
		if (!(iter & ref)) {
			if (b & 1)
				result |= iter;
			b >>= 1;
			nb--;
		}
		iter <<= 1;
	}
	return result;
}

void *check_ptr(void *ptr)
{
	if (!ptr) {
		fprintf(stderr, "memory depletion!\n");
		exit(1);
	}
	return ptr;
}

struct label *gen_labels(int count, int lenmin, int lenmax)
{
	struct label *result;
	int i;
	result = check_ptr(calloc(count, sizeof(struct label)));
	for (i = 0; i < count; i++) {
		int len = lenmin + (lenmin == lenmax ? 0 : r(lenmax-lenmin));
		result[i].label = check_ptr(calloc(1+len, 1));
		while (len)
			result[i].label[--len] = 'A' + (char)(r(26));
		result[i].rules = check_ptr(calloc(count, sizeof(char)));
	}

	return result;
}

struct label *read_labels(int count)
{
	struct label *result;
	int i;
	size_t tmp;

	result = check_ptr(calloc(count, sizeof(struct label)));
	for (i = 0; i < count; i++) {
		tmp = getline(&(result[i].label), &tmp, stdin);
		result[i].label[tmp-1] = 0;
		result[i].rules = check_ptr(calloc(count, sizeof(char)));
	}

	return result;
}

int code_to_string(int code, char *buffer)
{
	static char *flags = "rwxatl";
	int pos = 0;
	int len = 0;
	while (code) {
		if (code & 1)
			buffer[len++] = flags[pos];
		pos++;
		code >>= 1;
	}
	if (!len)
		buffer[len++] = '-';
	return len;
}

char **genrights(int count)
{
	char buffer[20];
	char **result;
	int i;
	result = check_ptr(calloc(sizeof *result, count));
	for (i = 0; i < count; i++) {
		int allow = random_code(0);
		int len = code_to_string(allow, buffer);
		if (!r(3)) {
			buffer[len++] = ' ';
			len += code_to_string(random_code(allow), buffer + len);
		}
		result[i] = check_ptr(strndup(buffer, len));
	}
	return result;
}

int pick_subj_label(struct label *labels, int nlab, int max_reoccurance)
{
	int startidx = r(nlab);
	int repeat = 0;
	int idx = startidx;
	while (labels[idx].counter >= max_reoccurance) {
		idx++;
		repeat++;
		idx %= nlab;
		if (repeat > nlab) {
			fprintf(stderr, "Wrong parameters");
			exit(-1);
		}
	}
	return idx;
}


int pick_obj_label(struct label *labels, int nlab, int max_reoccurance, int *subj)
{
	int startidx = r(nlab);
	int repeat = 0;
	int repeat_subj = 0;
	int idx = startidx;
	while (labels[idx].counter >= ((*subj == idx) ? max_reoccurance - 1 : max_reoccurance) ||
			labels[*subj].rules[idx] != 0) {
		idx++;
		repeat++;
		idx %= nlab;
		if (idx == startidx && repeat != 0) {
			(*subj)++;
			(*subj) %= nlab;
			repeat_subj++;
			if (repeat_subj > nlab) {
				fprintf(stderr, "Wrong parameters");
				exit(-1);
			} else
				repeat = 0;
		}
	}

	labels[*subj].counter++;
	labels[idx].counter++;
	labels[*subj].rules[idx] = 1;
	return idx;
}

int main(int argc, char **argv)
{
	int lab_cnt = 500;
	int rig_cnt = 100;
	int rul_cnt = 500;
	int lab_max = rul_cnt * 2;
	int mer_cnt = 0;
	int lab_stdin = 0;
	struct label *labels;
	char **rights;
	while (*++argv) {
		char c;
		int n;
		if (sscanf(*argv, "%1[lLru]=%d", &c, &n) == 2 && n > 0) {
			switch (c) {
			case 'l': lab_cnt = n; break;
			case 'r': rig_cnt = n; break;
			case 'u': rul_cnt = n; break;
			case 'L': lab_max = n; break;
			}
		} else if (sscanf(*argv, "%1[mi]=%d", &c, &n) == 2 && n >= 0) {
			switch (c) {
			case 'm': mer_cnt = n; break;
			case 'i': lab_stdin = n; break;
			}
		} else {
			fprintf(stderr, "usage: gen [[lLrumi]=VALUE]... (where VALUE is a number >= 0)\n");
			fprintf(stderr, "      l: number of labels in policy, l>0\n");
			fprintf(stderr, "      L: maximal number of each label reoccurance in policy, L>0\n");
			fprintf(stderr, "      u: number of unique rules (rules with different subject,object pair), u>0\n");
			fprintf(stderr, "      m: number of merges per each unique rule, m>=0\n");
			fprintf(stderr, "      r: number of different rights generated randomly, r>0\n");
			fprintf(stderr, "      i: i=0: generate labels, i>0: read labels from stdio, 0 by default\n");

			exit(1);
		}
	}
	if (lab_stdin)
		labels = read_labels(lab_cnt);
	else
		labels = gen_labels(lab_cnt, 4, 24);
	rights = genrights(rig_cnt);
	while (rul_cnt--) {
		int sub = pick_subj_label(labels, lab_cnt, lab_max);
		int obj = pick_obj_label(labels, lab_cnt, lab_max, &sub);
		int i;
		for (i = 0; i <= mer_cnt; i++)
			printf("%s %s %s\n", labels[sub].label, labels[obj].label, rights[r(rig_cnt)]);
	}
	return 0;
}
