#!/bin/bash

orig_cont=$1
new_cont=$2
iters_precopy=$3
migr_dst=$4

get_exec_pid() {
	cont_id=$1
	init_pid=`cat /run/containerd/io.containerd.runtime.v1.linux/moby/$cont_id/init.pid; echo`
	shim_pid=`cat /run/containerd/io.containerd.runtime.v1.linux/moby/$cont_id/shim.pid; echo`
	pid_list=`cat /proc/$shim_pid/task/$shim_pid/children; echo`

	for i in $pid_list; do
		echo $i | grep -v $init_pid
	done
}

get_exec_pid_v2() {
	cont_alias=$1
	init_pid=`docker inspect ${cont_alias} | grep \"Pid\" | awk -F '[", ]+' '{print $4}'`
	shim_pid=`ps -o ppid ${init_pid} | grep -v PPID | awk '{print $1}'`
	pid_list=`cat /proc/$shim_pid/task/$shim_pid/children; echo`

	for i in ${pid_list}; do
		echo $i | grep -v $init_pid
	done
}

mkdir /dev/shm/dump /dev/shm/dumprdma /dev/shm/restorerdma/ /dev/shm/workpath

#docker run -d --name test --hostname test --ulimit nofile=32768:32768 --net=host --device=/dev/infiniband/ --cap-add=ALL --privileged -v /dev/shm/:/dev/shm/ -v /dev/null/:/dev/null/ ubuntu2004:rdma $@

#sleep 30

ssh root@${migr_dst} `pwd`/utils/remote_start_cont.sh ${new_cont}
orig_cont_id=`docker inspect ${orig_cont} | grep Id | awk -F '[" ]+' '{print $4}'`
old_init_pid=`docker inspect ${orig_cont} | grep \"Pid\" | awk -F '[", ]+' '{print $4}'`

if [ -n "`ls /run/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id} 2> /dev/stdout > /dev/null`" ]; then
	docker_new=1
else
	docker_new=0
fi

if [ ${docker_new} -ne 0 ]; then
	for pid in `get_exec_pid_v2 ${orig_cont}`; do
		mkdir /dev/shm/restorerdma/$pid/
	done
else
	for pid in `get_exec_pid ${orig_cont_id}`; do
		mkdir /dev/shm/restorerdma/$pid/
	done
fi

runc --root /var/run/docker/runtime-runc/moby/ --log /dev/shm/${orig_cont_id}.json --log-format json checkpointrdma \
					--migr-dst ${migr_dst} \
					--image-path /dev/shm/restorerdma/ --work-path /dev/shm/workpath/ ${orig_cont_id}

mkdir /dev/shm/predump_img
cp /dev/shm/restorerdma/* /dev/shm/predump_img/ -r

scp -q -r /dev/shm/restorerdma/ root@${migr_dst}:/dev/shm/
ssh root@${migr_dst} `pwd`/utils/remote_prerestore.sh ${new_cont} ${migr_dst} `pwd`/utils/prerestore/rdma_prerestore

mkdir /dev/shm/restorerdma/checkpoint1/
if [ ${docker_new} -ne 0 ]; then
	for pid in `get_exec_pid_v2 ${orig_cont}`; do
		mkdir /dev/shm/restorerdma/checkpoint1/$pid/ -p
	done
else
	for pid in `get_exec_pid ${orig_cont_id}`; do
		mkdir /dev/shm/restorerdma/checkpoint1/$pid/ -p
	done
fi

for i in `j=1; while [ $j -le $iters_precopy ]; do echo $j; j=\`expr $j + 1\`; done`; do
	mkdir /dev/shm/restorerdma/checkpoint1/pre_$i -p
	runc --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id}/log.json --log-format json predump \
						--image-path /dev/shm/restorerdma/checkpoint1/pre_$i `if [ $i -ne 1 ]; then echo "--parent-path ../pre_\`expr $i - 1\`"; fi` \
						--work-path /var/lib/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id}/criu-work ${orig_cont_id}
done

echo "Ready to notify"
mkdir /dev/shm/dump_img
./src/wbs_external/wbs ${old_init_pid} /dev/shm/dump_img/
if [ ${docker_new} -ne 0 ]; then
	for pid in `get_exec_pid_v2 ${orig_cont}`; do
		./src/wbs_external/wbs ${pid} /dev/shm/dump_img/${pid}/
	done
else
	for pid in `get_exec_pid ${orig_cont_id}`; do
		./src/wbs_external/wbs ${pid} /dev/shm/dump_img/${pid}/
	done
fi
echo "Notify finish"
wbc_time=$(docker logs test 2> /dev/null | grep -oP "Wait-before-stop.*" | awk '{print $2}')

if [ ${docker_new} -ne 0 ]; then
	runc --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v2.task/moby/${orig_cont_id}/log.json --log-format json checkpoint \
					--image-path /dev/shm/dump_img `if [ $iters_precopy -gt 0 ]; then echo "--parent-path ./pre_${iters_precopy}"; fi` \
					--rdma-presetup --migr-dst ${migr_dst} \
					--work-path /run/containerd/io.containerd.runtime.v2.task/moby/${orig_cont_id}/work/criu-work ${orig_cont_id}
else
	runc --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id}/log.json --log-format json checkpoint \
					--image-path /dev/shm/dump_img `if [ $iters_precopy -gt 0 ]; then echo "--parent-path ./pre_${iters_precopy}"; fi` \
					--rdma-presetup --migr-dst ${migr_dst} \
					--work-path /var/lib/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id}/criu-work ${orig_cont_id}
fi
mkdir /dev/shm/dump_img/fdiff
cp `docker inspect ${orig_cont} | grep Upper | awk -F '[:," ]+' '{print $3}'`/* /dev/shm/dump_img/fdiff/ -r

rm /dev/shm/restorerdma/* -r
cp /dev/shm/dump_img/* /dev/shm/restorerdma/ -r

start=`date +"%s.%N"`
scp -q -r /dev/shm/restorerdma/ root@${migr_dst}:/dev/shm/
end=`date +"%s.%N"`
ssh root@${migr_dst} `pwd`/utils/remote_restore.sh ${new_cont}

scp -q -r root@${migr_dst}:/dev/shm/restore*.log /dev/shm/

transfer_time=`echo "scale=3; ($end - $start) * 1000.0" | bc`
checkpoint_time_raw=`cat /dev/shm/dump_*.log | tail -n 1 | awk -F '[()]+' '{print $2}'`
checkpoint_time=`echo "scale=3; $checkpoint_time_raw * 1000.0" | bc`
start_raw=`cat /dev/shm/restore*.log | grep "Full restore" | awk -F '[()]+' '{print $2}'`
start=`echo "scale=3; $start_raw * 1000.0" | bc`
end_raw=`cat /dev/shm/restore*.log | tail -n 1 | awk -F '[()]+' '{print $2}'`
end=`echo "scale=3; $end_raw * 1000.0" | bc`
restore_time_total=`echo "scale=3; $end - $start" | bc`
start_raw=`cat /dev/shm/restore*.log | grep "metadata" | awk -F '[()]+' '{print $2}'`
start=`echo "scale=3; $start_raw * 1000.0" | bc`
end_raw=`cat /dev/shm/restore*.log | grep "Restore RDMA communication" | awk -F '[()]+' '{print $2}'`
end=`echo "scale=3; $end_raw * 1000.0" | bc`
restore_comm=`echo "scale=3; $end - $start" | bc`
restore_time=`echo "scale=3; $restore_time_total - $restore_comm" | bc`
echo "DumpOthers: ${checkpoint_time} ms"
echo "Transfer: ${transfer_time} ms"
echo "FullRestore: ${restore_time} ms"
echo "Wait-before-stop: ${wbc_time} ms"

cd /dev/shm/
rm *.json checkpoint_time *.log dump_img/ predump_img/ restorerdma/ workpath *.sock dump dumprdma -r
ssh root@${migr_dst} rm /dev/shm/*.json /dev/shm/checkpoint_time /dev/shm/*.log /dev/shm/dump_img/ /dev/shm/predump_img/ \
						/dev/shm/restorerdma/ /dev/shm/workpath /dev/shm/*.sock /dev/shm/dump /dev/shm/dumprdma -r
