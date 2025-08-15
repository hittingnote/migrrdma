#!/bin/bash

pre_setup=$1
migr_who=$2
partner=$3
migr_dst=$4
ibdev=$5

shift 5

cd ../

ssh root@${partner} `pwd`/src/migrrdma_daemon/migrrdma_daemon ${ibdev} &> /dev/null &

if [ "${migr_who}" == "recv" ]; then
	./rdma_migr_demo.sh ${pre_setup} ${migr_dst} $@ -d ${ibdev} --use_old_post_send --run_infinitely |
				grep -E "DumpRDMA|DumpOthers|Transfer|RestoreRDMA|FullRestore" &
	sleep 2
	ssh root@${partner} $@ -d ${ibdev} --use_old_post_send --run_infinitely \
				$(show_gids | grep ${ibdev} | tail -n 1 | awk '{print $5}') 2> /dev/null |
			       	while read LINE; do
					if [ -n "`echo $LINE | grep -E \"GID|local|remote\"`" ]; then
						continue
					fi
					echo "[FROM Partner (Sender)]: $LINE" > /dev/stderr
				done &
elif [ "${migr_who}" == "send" ]; then
	ssh root@${partner} $@ -d ${ibdev} --use_old_post_send --run_infinitely 2> /dev/null |
				while read LINE; do
					if [ -n "`echo $LINE | grep -E \"GID|local|remote\"`" ]; then
						continue
					fi
					echo "[FROM Partner (Receiver)]: $LINE" > /dev/stderr
				done &
	sleep 2
	./rdma_migr_demo.sh ${pre_setup} ${migr_dst} $@ -d ${ibdev} --use_old_post_send --run_infinitely ${partner} |
				grep -E "DumpRDMA|DumpOthers|Transfer|RestoreRDMA|FullRestore" &
else
	echo "Invalid argument!" > /dev/stderr
fi

sleep 60

docker rm -f test
ssh root@${migr_dst} docker rm -f test1
ssh root@${migr_dst} docker rm -f test1
ssh root@${partner} pkill -9 `echo $@ | awk '{print $1}'`
ssh root@${partner} pkill -9 migrrdma_daemon

