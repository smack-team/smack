#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>

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
 * auxilliary function to sort arrays of strings with qsort
 */
int qsort_aux_strings(const void *a, const void *b)
{
	return strcmp(*(const char const * const *)a, *(const char const * const *)b);
}

/*
 * Generates an array of 'count' labels randomly generated.
 * The generated labels have from 'lenmin' to 'lenmax' characters.
 * They are only alphabetics then valid for Smack.
 * 
 * Returns: the generated array.
 */
char **gen_labels(int count, int lenmin, int lenmax)
{
	char **result;
	int i, len;

	result = check_ptr(calloc(count, sizeof*result));
	for (i = 0; i < count; i++) {
		len = lenmin + (lenmin == lenmax ? 0 : alea(lenmax-lenmin));
		result[i] = check_ptr(calloc(1 + len, 1));
		while (len)
			result[i][--len] = 'A' + (char)(alea(26));
	}

	qsort(result, count, sizeof * result, qsort_aux_strings);
	return result;
}

/*
 * Reads the array of 'count' labels from stdin.
 * No check is performed on labels then there is no
 * guaranty of validity for Smack.
 * 
 * Returns: the read array.
 */
char **read_labels(int count)
{
	char **result;
	int i;
	size_t tmp;

	result = check_ptr(calloc(count, sizeof*result));
	for (i = 0; i < count; i++) {
		tmp = getline(&(result[i]), &tmp, stdin);
		result[i][tmp - 1] = 0;
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
 * 'permodif' indicates what percentage of the rights should be
 * modification rights.
 * 
 * Returns: the generated array.
 */
char **genrights(int count, int permodif)
{
	char buffer[20];
	char **result;
	int i, allow, len;

	result = check_ptr(calloc(sizeof *result, count));
	for (i = 0; i < count; i++) {
		allow = random_code(0);
		len = code_to_string(allow, buffer);
		if (permodif > alea(100)) {
			buffer[len++] = ' ';
			len += code_to_string(random_code(allow), buffer + len);
		}
		result[i] = check_ptr(strndup(buffer, len));
	}

	return result;
}

/*
 * Generate the set of 'nrules' rules for 'nlab' labels with
 * the constraint that each label is used a maximum count of
 * 'maxoccur' times (either as subject or as label). The result
 * is sorted unless 'shuffle' is set to a non zero value.
 *
 * The rules are generated as integers for the rule of value
 * R, the index of the subject is R/'nlab' and the object index
 * is R%'nlab'. (note: subject and object are exchangeable).
 *
 * Returns: An array of 'nrules' integers encoding the generated
 * rules encoded as explained above.
 */
int *make_the_rules(int nlab, int maxoccur, int nrules, int shuffle)
{
	int i, j, v, n, isubj, iobj, halfoccur, restoccur, offset;
	int *result, *permut;

	/* check the ability to process such count of labels */
	if (INT_MAX / nlab < nlab) {
		fprintf(stderr, "Too many labels!!!! Sorry, I can't.\n");
		exit(1);
	}

	/* check the constraint */
	if (maxoccur * nlab < 2 * nrules) {
		fprintf(stderr, "The constraint can't be satisfied by nature.\n");
		exit(1);
	}

	/* allocate the result */
	result = check_ptr(calloc(sizeof * result, (nlab * maxoccur) / 2));

	/* a permutation for shuffling */
	if (shuffle) {
		permut = check_ptr(calloc(sizeof * result, nlab));
		for (i = 0 ; i < nlab ; i++)
			permut[i] = i;
		while(i) {
			j = alea(i--);
			v = permut[i];
			permut[i] = permut[j];
			permut[j] = v;
		}
	} else 
		permut = NULL;

	/* init the algo */
	halfoccur = maxoccur / 2;
	restoccur = maxoccur & 1;
	if (halfoccur + restoccur == nlab) {
		offset = 0;
	} else {
		offset = 1;
	}

	/* compute the raw result */
	i = 0;
	for (isubj = 0 ; isubj < nlab ; isubj++) {
		iobj = (isubj + offset) % nlab;
		n = halfoccur + (restoccur & isubj);
		v = iobj + n - nlab;
		if (v <= 0)
			v = 0;
		for (j = 0 ; j < n ; j++) {
			result[i + v] = shuffle ? (permut[isubj] * nlab + permut[iobj])
							: (isubj * nlab + iobj);
			iobj = (iobj + 1) % nlab;
			v = (v + 1) % n;
		}
		i += n;
	}

	/* frightened that algo is wrong */
	if (i != (nlab * maxoccur) / 2) {
		fprintf(stderr, "Internal error.\n");
		exit(1);
	}

	if (shuffle) {
		/* handle shuffling of the rules */
		free(permut);
		for (n = 3 ; n ; n--) {
			i = (nlab * maxoccur) / 2;
			while(i) {
				j = alea(i--);
				v = result[i];
				result[i] = result[j];
				result[j] = v;
			}
		}
	} else if (nrules < i) {
		/* reduce the count of rules while keeping it ordered */
		for (n = 0, j = 0 ; j < i ; j++)
			if (alea(i - j) < nrules - n)
				result[n++] = result[j];
	}


	return result;
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
		"      s: shuffles or sort the result. s=0, default, sorts. s>0, shuffles.\n" 
		"      p: percentage of modification rules, from 0 to 100, default: 33\n"
	);
}

/* main */
int main(int argc, char **argv)
{
	int shuffle = 0;
	int lab_cnt = 500;
	int rig_cnt = 100;
	int rul_cnt = 500;
	int lab_max = rul_cnt * 2;
	int mer_cnt = 0;
	int lab_stdin = 0;
	int permodif = 33;

	char **labels;
	char **rights, c;
	int n, r, m, sub, obj;
	int *rules;

	/* read options */
	while (*++argv) {
		if (sscanf(*argv, "%1[lLru]=%d", &c, &n) == 2 && n > 0) {
			switch (c) {
			case 'l': lab_cnt = n; break;
			case 'r': rig_cnt = n; break;
			case 'u': rul_cnt = n; break;
			case 'L': lab_max = n; break;
			}
		} else if (sscanf(*argv, "%1[misp]=%d", &c, &n) == 2 && n >= 0) {
			switch (c) {
			case 'm': mer_cnt = n; break;
			case 'i': lab_stdin = n; break;
			case 's': shuffle = !!n; break;
			case 'p': permodif = n; break;
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
	rights = genrights(rig_cnt, permodif);

	/* generate the rules */
	rules = make_the_rules(lab_cnt, lab_max, rul_cnt, shuffle);
	for (r = 0 ; r < rul_cnt ; r++) {
		n = rules[r];
		sub = n / lab_cnt;
		obj = n % lab_cnt;
		for (m = 0; m <= mer_cnt; m++)
			printf("%s %s %s\n", labels[sub], labels[obj], rights[alea(rig_cnt)]);
	}

	return 0;
}
