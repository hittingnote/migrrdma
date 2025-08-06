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

mkdir /dev/shm/dump /dev/shm/dumprdma /dev/shm/restorerdma/ /dev/shm/workpath

#docker run -d --name test --hostname test --ulimit nofile=32768:32768 --net=host --device=/dev/infiniband/ --cap-add=ALL --privileged -v /dev/shm/:/dev/shm/ -v /dev/null/:/dev/null/ ubuntu2004:rdma $@

#sleep 30

docker run -d --name ${new_cont} --hostname ${new_cont} --ulimit nofile=32768:32768 --net=host --device=/dev/infiniband/ --cap-add=ALL --privileged -v /dev/shm/:/dev/shm/ -v /dev/null/:/dev/null/ ubuntu2004:rdma /init_proc
orig_cont_id=`docker inspect ${orig_cont} | grep Id | awk -F '[" ]+' '{print $4}'`
new_cont_id=`docker inspect ${new_cont} | grep Id | awk -F '[" ]+' '{print $4}'`
old_init_pid=`docker inspect ${orig_cont} | grep \"Pid\" | awk -F '[", ]+' '{print $4}'`
new_init_pid=`docker inspect ${new_cont} | grep \"Pid\" | awk -F '[", ]+' '{print $4}'`

for pid in `get_exec_pid ${orig_cont_id}`; do
	mkdir /dev/shm/restorerdma/$pid/
done

runc --root /var/run/docker/runtime-runc/moby/ --log /dev/shm/${orig_cont_id}.json --log-format json checkpointrdma \
					--migr-dst ${migr_dst} \
					--image-path /dev/shm/restorerdma/ --work-path /dev/shm/workpath/ ${orig_cont_id}

mkdir /dev/shm/predump_img
cp /dev/shm/restorerdma/* /dev/shm/predump_img/ -r

./utils/prerestore/rdma_prerestore --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id}.json \
					--log-format json rdmarestore --image-path /dev/shm/restorerdma/ \
					--work-path /var/lib/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id} \
					--rdma-presetup \
					--detach --pid-file /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id}/init.pid -no-subreaper \
					--bundle /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id} ${new_cont_id} < /proc/${new_init_pid}/fd/0 > /proc/${new_init_pid}/fd/1 2> /proc/${new_init_pid}/fd/2

mkdir /dev/shm/restorerdma/checkpoint1/
for pid in `get_exec_pid ${orig_cont_id}`; do
	mkdir /dev/shm/restorerdma/checkpoint1/$pid/ -p
done

for i in `j=1; while [ $j -le $iters_precopy ]; do echo $j; j=\`expr $j + 1\`; done`; do
	mkdir /dev/shm/restorerdma/checkpoint1/pre_$i -p
	runc --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id}/log.json --log-format json predump \
						--image-path /dev/shm/restorerdma/checkpoint1/pre_$i `if [ $i -ne 1 ]; then echo "--parent-path ../pre_\`expr $i - 1\`"; fi` \
						--work-path /var/lib/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id}/criu-work ${orig_cont_id}
done

echo "Ready to notify"
mkdir /dev/shm/dump_img
start=`date +"%s.%N"`
./src/wbs_external/wbs ${old_init_pid} /dev/shm/dump_img/
for pid in `get_exec_pid ${orig_cont_id}`; do
	./src/wbs_external/wbs ${pid} /dev/shm/dump_img/${pid}/
done
end=`date +"%s.%N"`
echo "Notify finish"
wbc_time=`echo "scale=3; ( $end - $start ) * 1000.0 / 1.0" | bc`

runc --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id}/log.json --log-format json checkpoint \
					--image-path /dev/shm/dump_img `if [ $iters_precopy -gt 0 ]; then echo "--parent-path ./pre_${iters_precopy}"; fi` \
					--rdma-presetup --migr-dst ${migr_dst} \
					--work-path /var/lib/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id}/criu-work ${orig_cont_id}
mkdir /dev/shm/dump_img/fdiff
cp `docker inspect ${orig_cont} | grep Upper | awk -F '[:," ]+' '{print $3}'`/* /dev/shm/dump_img/fdiff/ -r

rm /dev/shm/restorerdma/* -r
cp /dev/shm/dump_img/* /dev/shm/restorerdma/ -r

cp /dev/shm/restorerdma/fdiff/* `docker inspect ${new_cont} | grep Upper | awk -F '[:," ]+' '{print $3}'`/ -r
runc --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id}.json \
					--log-format json restore --image-path /dev/shm/restorerdma/ \
					${new_cont_id}

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
echo "Checkpoint time: ${checkpoint_time} ms"
echo "Restore time: ${restore_time} ms"
echo "Wait-before-copy: ${wbc_time} ms"

cd /dev/shm/
rm *.json checkpoint_time *.log dump_img/ predump_img/ restorerdma/ workpath *.sock dump dumprdma -r

