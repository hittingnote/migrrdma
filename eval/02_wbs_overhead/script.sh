#!/bin/bash

cd ..

ulimit -n 32768

echo -e "#MsgSize\t\"WaitBeforeStop\"\tBlackout"

for i in 512 32768 262144 2097152 16777216; do
	echo -n "$i"
	./eval_basic.sh with_pre_setup send 10.10.1.1 10.10.1.1 mlx5_2 ib_send_bw -s $i -r 64 -t 64 > tmp.data
	echo -n -e "\t`cat tmp.data | grep \"Wait-before-stop\" | awk '{print $2}'`"
	sum=0.0
	for key in DumpOthers Transfer FullRestore; do
		this_num=`cat tmp.data | grep $key | awk '{print $2}'`
		sum=`echo "scale=6; $sum + $this_num" | bc`
	done
	echo -e "\t${sum}"
	echo -e "\"\""
done

rm tmp.data

