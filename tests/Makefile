all: policies

clean:
	rm -rf ./out ./generator

generator: generator.c
	gcc -Wall -O3 generator.c -o ./generator

policies: ./generator ./make_policies.bash
	./make_policies.bash ./generator

policies_from_labels: ./generator ./make_policies.bash labels
	./make_policies.bash ./generator labels
