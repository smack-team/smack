#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int r(int count) {
	return random() % count;
}

int cb(int n) {
	int result = 0;
	while(n) {
		result += n & 1;
		n >>= 1;
	}
	return result;
}

int rc(int ref) {
	int nb = 6 - cb(ref);
	int b = r(1 << nb);
	int iter = 1;
	int result = 0;
	while(nb) {
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

void* check(void *ptr) {
	if(!ptr){
		fprintf(stderr,"memory depletion!\n");
		exit(1);
	}
	return ptr;
}

char** genlabels(int count, int lenmin, int lenmax) {
	char **result;
	int i;
	result = check(calloc(sizeof*result,count));
	for(i=0;i<count;i++) {
		int len = lenmin + (lenmin==lenmax ? 0 : r(lenmax-lenmin));
		result[i] = check(calloc(1+len,1));
		while(len) result[i][--len] = 'A' + (char)(r(26));
	}
	return result;
}

int c2s(int code, char *buffer)
{
	static char *flags = "rwxatl";
	int pos = 0;
	int len = 0;
	while (code) {
		if (code & 1) buffer[len++] = flags[pos];
		pos++;
		code >>= 1;
	}
	if (!len) buffer[len++] = '-';
	return len;
}

char** genrights(int count) {
	char buffer[20];
	char **result;
	int i;
	result = check(calloc(sizeof*result,count));
	for(i=0;i<count;i++) {
		int allow = rc(0);
		int len = c2s(allow,buffer);
		if (!r(3)) {
			buffer[len++] = ' ';
			len += c2s(rc(allow),buffer+len);
		}
		result[i] = check(strndup(buffer,len));
	}
	return result;
}

int main(int argc, char **argv) {
	int nlab = 5;
	int nrig = 100;
	int nout = 500;
	char **labels, **rights;
	while(*++argv) {
		char c;
		int n;
		if (sscanf(*argv,"%1[lro]=%d",&c,&n)==2 && n>0) {
			switch(c) {
			case 'l': nlab=n; break;
			case 'r': nrig=n; break;
			case 'o': nout=n; break;
			}
		}
		else {
			fprintf(stderr,"usage: gen [[lro]=VALUE]... (where VALUE is a number > 0)\n");
			exit(1);
		}
	}
	labels = genlabels(nlab,4,8);
	rights = genrights(nrig);
	while(nout--) 
		printf("%s %s %s\n", labels[r(nlab)], labels[r(nlab)], rights[r(nrig)]);
	return 0;
}

