#!/bin/bash

LABELS=(`aspell dump master | tr "'" "_" | shuf | head -200`)
ACCESS=('r' 'w' 'x' 'a' 't')
LABELS_LEN=${#LABELS[@]}

function get_access_code()
{
    local result
    for i in `seq 0 1 4`; do
	if test `expr $RANDOM % 2` -eq 0; then
	    result="$result${ACCESS[$i]}"
	else
	    result="$result-"
	fi
    done

    eval "$1=$result"
}

function print_access_rules()
{
    for i in `seq 0 1 10000`; do
	local subject_i=`expr $RANDOM % $LABELS_LEN`
	local object_i=`expr $RANDOM % $LABELS_LEN`
	local acc=''
	get_access_code acc
	echo ${LABELS[$subject_i]} ${LABELS[$object_i]} $acc >> $1
    done
}

for i in `seq 0 1 200`; do
	print_access_rules $i.txt
done
