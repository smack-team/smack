#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct label {
	char *label;	/* the label */
	int counter;	/* count of emitted occurences of the label within rules */
	char *rules;	/* indicator of the object referenced by this subject label in emitted rules */
};

/*
 * Returns a new random number from 0 to 'count'-1.
 * 
 * Examples:
 * 	alea(5) -> 2
 * 	alea(5) -> 0
 */
int alea(int count)
{
	return random() % count;
}

/*
 * Returns the count of bits set to one in
 * the number 'n'.
 * 
 * Examples:
 * 	count_set_bits(30) -> 4
 * 	count_set_bits(5) -> 1
 */
int count_set_bits(int n)
{
	int result = 0;
	while (n) {
		result += n & 1;
		n >>= 1;
	}
	return result;
}

/*
 * Gets a random access code such that
 * result & 'ref' == 0.
 * 
 * This coulded be coded as: return alea(1<<6) & ~ref;
 * but using the algorithm below may improves
 * the randomness (perhaps).
 * 
 * Examples:
 * 	random_code(0) -> 17 == 021
 * 	random_code(17) -> 44 == 054
 */
int random_code(int ref)
{
	int nb = 6 - count_set_bits(ref);
	int b = alea(1 << nb);
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

/*
 * Anti NULL pointer barrier.
 * 
 * Returns the given pointer except if that pointer is NULL
 * in which case a message is prompted to stderr stating
 * the memory depletion and the program is exited with
 * a return code of 1.
 */
void *check_ptr(void *ptr)
{
	if (!ptr) {
		fprintf(stderr, "memory depletion!\n");
		exit(1);
	}
	return ptr;
}

/*
 * Generates an array of 'count' labels randomly generated.
 * The generated labels have from 'lenmin' to 'lenmax' characters.
 * They are only alphabetics then valid for Smack.
 * 
 * Returns: the generated array. For each label, the structure
 * is initialised such that .count==0 and .rules[0..'count'-1]==0.
 */
struct label *gen_labels(int count, int lenmin, int lenmax)
{
	struct label *result;
	int i, len;

	result = check_ptr(calloc(count, sizeof(struct label)));
	for (i = 0; i < count; i++) {
		len = lenmin + (lenmin == lenmax ? 0 : alea(lenmax-lenmin));
		result[i].label = check_ptr(calloc(1 + len, 1));
		while (len)
			result[i].label[--len] = 'A' + (char)(alea(26));
		result[i].rules = check_ptr(calloc(count, sizeof(char)));
	}

	return result;
}

/*
 * Reads the array of 'count' labels from stdin.
 * No check is performed on labels then there is no
 * guaranty of validity for Smack.
 * 
 * Returns: the read array. For each label, the structure
 * is initialised such that .count==0 and .rules[0..'count'-1]==0.
 */
struct label *read_labels(int count)
{
	struct label *result;
	int i;
	size_t tmp;

	result = check_ptr(calloc(count, sizeof(struct label)));
	for (i = 0; i < count; i++) {
		tmp = getline(&(result[i].label), &tmp, stdin);
		result[i].label[tmp - 1] = 0;
		result[i].rules = check_ptr(calloc(count, sizeof(char)));
	}

	return result;
}

/*
 * Computes into 'buffer' the string corresponding to the
 * given access 'code'. No null character is appended at
 * the end of the generated string.
 * 
 * The 'buffer' MUST have at least 6 characters.
 * 
 * Returns the length of the string generated.
 * 
 * Examples:
 * 	code_to_string(5) -> 2, "rx"
 * 	code_to_string(19) -> 3, "rwt"
 */
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

/*
 * Generates an array of 'count' access rights randomly generated.
 * 
 * Statistically 1/3 of the generated rights are modification rights
 * and 2/3 are setting rights.
 * 
 * Returns: the generated array.
 */
char **genrights(int count)
{
	char buffer[20];
	char **result;
	int i, allow, len;

	result = check_ptr(calloc(sizeof *result, count));
	for (i = 0; i < count; i++) {
		allow = random_code(0);
		len = code_to_string(allow, buffer);
		if (!alea(3)) {
			buffer[len++] = ' ';
			len += code_to_string(random_code(allow), buffer + len);
		}
		result[i] = check_ptr(strndup(buffer, len));
	}

	return result;
}

/*
 * Chooses randomly a subject label within the array of 'labels' that have
 * 'nlab' elements with the constraint that a label cant be choosen
 * more than 'max_reoccurance' times.
 * 
 * If the constraint can't be ensured, a message is prompted to stderr
 * and the program exited with the status 1.
 * 
 * The field .counter is read to know the count of previous occurence
 * for the labels.
 * 
 * Returns: the index of the selected label within 'labels'.
 */
int pick_subj_label(struct label *labels, int nlab, int max_reoccurance)
{
	int startidx = alea(nlab);
	int repeat = 0;
	int idx = startidx;

	while (labels[idx].counter >= max_reoccurance) {
		idx++;
		repeat++;
		idx %= nlab;
		if (repeat > nlab) {
			fprintf(stderr, "Wrong parameters");
			exit(1);
		}
	}

	return idx;
}

/*
 * Chooses randomly an object label associated to the nominal subject
 * label of index *'subj' within the array of 'labels' that have
 * 'nlab' elements with the constraints that:
 *  - a label can't be choosen more than 'max_reoccurance' times
 *  - the subject index is nominaly *'subj'
 * 
 * The subject is nominaly of index *'subj' what means that is the
 * constraint of occurences can't be achieved with that nominal
 * subject, an other subject is tried for use.
 * 
 * If the constraint can't be ensured, a message is prompted to stderr
 * and the program exited with the status 1.
 * 
 * The field .counter is read to know the count of previous occurence
 * for the labels (object or subject).
 * 
 * The array labels[idxsub].rules[idxobj] is read to check is the
 * rule was already given.
 * 
 * When the pair (subject, object) is found, the related occurence
 * data of 'labels' are updated as a side effect.
 * 
 * Returns: the index of the selected object label within 'labels' and
 * the index of the finally selected subject label in *'subj'.
 */
int pick_obj_label(struct label *labels, int nlab, int max_reoccurance, int *subj)
{
	int startidx = alea(nlab);
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
				exit(1);
			} else
				repeat = 0;
		}
	}

	labels[*subj].counter++;
	labels[idx].counter++;
	labels[*subj].rules[idx] = 1;

	return idx;
}

/* displays the usage */
void usage()
{
	fprintf(stderr,
		"usage: gen [[lLrumi]=VALUE]... (where VALUE is a number >= 0)\n"
		"      l: number of labels in policy, l>0\n"
		"      L: maximal number of each label reoccurance in policy, L>0\n"
		"      u: number of unique rules (rules with different subject, object pair), u>0\n"
		"      m: number of merges per each unique rule, m>=0\n"
		"      r: number of different rights generated randomly, r>0\n"
		"      i: i=0: generate labels, i>0: read labels from stdio, 0 by default\n"
	);
}

/* main */
int main(int argc, char **argv)
{
	int lab_cnt = 500;
	int rig_cnt = 100;
	int rul_cnt = 500;
	int lab_max = rul_cnt * 2;
	int mer_cnt = 0;
	int lab_stdin = 0;

	struct label *labels;
	char **rights, c;
	int n, i, sub, obj;

	/* read options */
	while (*++argv) {
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
			usage();
			exit(1);
		}
	}

	/* create data: labels and rights */
	if (lab_stdin)
		labels = read_labels(lab_cnt);
	else
		labels = gen_labels(lab_cnt, 4, 24);
	rights = genrights(rig_cnt);

	/* generate the rules */
	while (rul_cnt--) {
		sub = pick_subj_label(labels, lab_cnt, lab_max);
		obj = pick_obj_label(labels, lab_cnt, lab_max, &sub);
		for (i = 0; i <= mer_cnt; i++)
			printf("%s %s %s\n", labels[sub].label, labels[obj].label, rights[alea(rig_cnt)]);
	}
	return 0;
}
