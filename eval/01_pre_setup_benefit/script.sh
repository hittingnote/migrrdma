#!/bin/bash

cd ..

ulimit -n 32768

echo -e "#QP\tTotalDump\tDumpRDMA\tDumpOthers\tTransfer\tPartialRestore\tRestoreRDMA\tFullRestore\tTotalDump\tDumpRDMA\tDumpOthers\tTransfer\tPartialRestore\tRestoreRDMA\tFullRestore"

for i in 1 8 64 512 4096; do
	echo -n "$i"
	./eval_basic.sh wo_pre_setup send 10.10.1.1 10.10.1.1 mlx5_2 ib_send_bw -s 4096 -r 64 -t 64 -q $i > tmp.data
	echo -e -n "\t-"
	echo -e -n "\t`cat tmp.data | grep DumpRDMA | awk '{print $2}'`"
	echo -e -n "\t`cat tmp.data | grep DumpOthers | awk '{print $2}'`"
	echo -e -n "\t`cat tmp.data | grep Transfer | awk '{print $2}'`"
	echo -e -n "\t0"
	echo -e -n "\t`cat tmp.data | grep RestoreRDMA | awk '{print $2}'`"
	echo -e -n "\t`cat tmp.data | grep FullRestore | awk '{print $2}'`"
	./eval_basic.sh with_pre_setup send 10.10.1.1 10.10.1.1 mlx5_2 ib_send_bw -s 4096 -r 64 -t 64 -q $i > tmp.data
	echo -e -n "\t-"
	echo -e -n "\t0"
	echo -e -n "\t`cat tmp.data | grep DumpOthers | awk '{print $2}'`"
	echo -e -n "\t`cat tmp.data | grep Transfer | awk '{print $2}'`"
	echo -e -n "\t0"
	echo -e -n "\t0"
	echo -e "\t`cat tmp.data | grep FullRestore | awk '{print $2}'`"
done

rm tmp.data

