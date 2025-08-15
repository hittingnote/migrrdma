#!/bin/bash

cat $1 | while read LINE; do
	if [ -n "`echo $LINE | grep \"\#QP\"`" ]; then
		continue
	fi

	nqp=`echo $LINE | awk '{print $1}'`
	sum=0.0
	for n in `echo $LINE | awk '{printf "%s\n%s\n%s\n%s\n%s\n%s\n", $3,$4,$5,$6,$7,$8}'`; do
		sum=`echo "$sum + $n" | bc`
	done

	echo -n "$nqp"
	index=0
	for n in $LINE; do
		if [ "$nqp" == "$n" ]; then
			continue
		fi
		if [ "$n" == "-" ]; then
			echo -n -e "\t-"
			continue
		fi
		o=`echo "scale=6; $n / $sum" |bc`
		echo -n -e "\t$o"
		index=`expr $index + 1`
		if [ $index -ge 6 ]; then
			echo -e "\t-\t0\t0\t0\t0\t0\t0"
			echo -n -e "${nqp}\t-\t0\t0\t0\t0\t0\t0"
			index=-6
		fi
	done
	echo ""
	echo "\"\""
done

