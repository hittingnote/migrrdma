#!/bin/bash

iters_precopy=$1

shift 1

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

docker run -d --name test --hostname test --ulimit nofile=32768:32768 --net=host --device=/dev/infiniband/ --cap-add=ALL --privileged -v /dev/shm/:/dev/shm/ -v /dev/null/:/dev/null/ ubuntu2004:rdma /init_proc

docker exec -it test bash
sleep 30

docker run -d --name test1 --hostname test1 --ulimit nofile=32768:32768 --net=host --device=/dev/infiniband/ --cap-add=ALL --privileged -v /dev/shm/:/dev/shm/ -v /dev/null/:/dev/null/ ubuntu2004:rdma /init_proc
orig_cont_id=`docker inspect test | grep Id | awk -F '[" ]+' '{print $4}'`
new_cont_id=`docker inspect test1 | grep Id | awk -F '[" ]+' '{print $4}'`
old_init_pid=`docker inspect test | grep \"Pid\" | awk -F '[", ]+' '{print $4}'`
new_init_pid=`docker inspect test1 | grep \"Pid\" | awk -F '[", ]+' '{print $4}'`
#mkdir /var/lib/docker/containers/${new_cont_id}/checkpoints/restorerdma/

for pid in `get_exec_pid ${orig_cont_id}`; do
	mkdir /dev/shm/restorerdma/$pid/
	./rdma_plugin/rdma_plugin ${pid} /dev/shm/restorerdma/$pid/ 192.168.2.15
done

runc --root /var/run/docker/runtime-runc/moby/ --log /dev/shm/${orig_cont_id}.json --log-format json checkpointrdma \
					--image-path /dev/shm/restorerdma/ --work-path /dev/shm/workpath/ ${orig_cont_id}

#cp /var/lib/docker/containers/${new_cont_id}/checkpoints/restorerdma/* /dev/shm/restorerdma/ -r

./rdma_plugin/rdma_plugin ${old_init_pid} /dev/shm/restorerdma/ 192.168.2.15

mkdir /dev/shm/predump_img
cp /dev/shm/restorerdma/* /dev/shm/predump_img/ -r

prerestore/rdma_prerestore --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id}.json \
					--log-format json rdmarestore --image-path /dev/shm/restorerdma/ \
					--work-path /var/lib/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id} \
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

# cp /dev/shm/restorerdma/* /dev/shm/dumprdma/ -r

echo "Ready to notify"
mkdir /dev/shm/dump_img
start=`date +"%s.%N"`
./rdma_plugin/rdma_plugin ${old_init_pid} /dev/shm/dump_img/
for pid in `get_exec_pid ${orig_cont_id}`; do
	./rdma_plugin/rdma_plugin ${pid} /dev/shm/dump_img/${pid}/
done
end=`date +"%s.%N"`
echo "Notify finish"
wbc_time=`echo "scale=3; ( $end - $start ) * 1000.0 / 1.0" | bc`

runc --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id}/log.json --log-format json checkpoint \
					--image-path /dev/shm/dump_img `if [ $iters_precopy -gt 0 ]; then echo "--parent-path ./pre_${iters_precopy}"; fi` \
					--work-path /var/lib/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id}/criu-work ${orig_cont_id}
mkdir /dev/shm/dump_img/fdiff
cp `docker inspect test | grep Upper | awk -F '[:," ]+' '{print $3}'`/* /dev/shm/dump_img/fdiff/ -r

rm /dev/shm/restorerdma/* -r
cp /dev/shm/dump_img/* /dev/shm/restorerdma/ -r

cp /dev/shm/restorerdma/fdiff/* `docker inspect test1 | grep Upper | awk -F '[:," ]+' '{print $3}'`/ -r
runc --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id}.json \
					--log-format json restore --image-path /dev/shm/restorerdma/ \
					${new_cont_id}

stat_wait_before_copy/calculate
echo "Wait-before-copy: ${wbc_time} ms"

