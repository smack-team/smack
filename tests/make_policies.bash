#!/bin/bash
#This script generates smack rule policies with random rules for test purposes.

if [ $# -eq 2 ]
then
	test ! -f "$2" && echo "no such file: $2" && exit 1;
	labs_cnt=`cat "$2" | wc -l`
	I="i=1"
	in="$2"

elif [ $# -eq 1 ]
then
	labs_cnt=1024
	in=/dev/null
else
	echo wrong parameters
	exit 1
fi


generator="$1"
outdir=./out/
test -d "$outdir" || mkdir "$outdir"

#m stands for number of merges per unique subject/object pair in policy
#number of merges in whole policy would be m*u, u is number of unique rules
for m in 0 1 2 4 9
do
	#power stands for log2 of number of different labels in policy
	for power in `seq 3 10`
	do
		#l stands for number of different labels in policy
		l=$(echo 2^$power | bc)

		if [ $labs_cnt -ge $l ]
		then
			for type in min 2min log max
			do
			case $type in
			min)  u=$((l/2)); L=1;; #minimal policy (each label occurs only once in policy)
			2min) u=$l; L=2;; #another minimal policy (each label occurs twice in policy)
			log) u=$((l*power)); L=$((power*2));; #medium sized policy (each label occurs 2log2(l) times in policy)
			max) u=$((l*l)); L=$((l*2));; #maximally dense policy (each label occurs l*2 times in policy)
			esac

			outfile="$outdir""$type""$l""m$m"
			echo generating $outfile
			"$generator" l=$l u=$u L=$L m=$m $I < $in | shuf > $outfile

			#for merged policy make additionally sorted policy
			if [ $m -eq 0 ]
			then
				echo generating "$outdir""$type""$l""sorted"
				sort  $outfile > "$outdir""$type""$l""sorted"
			fi
			done;
		fi
	done
done
