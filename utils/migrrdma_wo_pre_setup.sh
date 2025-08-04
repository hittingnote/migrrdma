#!/bin/bash

orig_cont=$1
new_cont=$2
iters_precopy=$3
migr_dst=$4

mkdir /dev/shm/dump /dev/shm/dumprdma /dev/shm/restorerdma/ /dev/shm/workpath

#docker run -d --name test --hostname test --net=host --device=/dev/infiniband/ --cap-add=ALL --privileged -v /dev/shm/:/dev/shm/ -v /dev/null/:/dev/null/ ubuntu2004:rdma $@

#sleep 27

docker run -d --name ${new_cont} --hostname ${new_cont} --net=host --device=/dev/infiniband/ --cap-add=ALL --privileged -v /dev/shm/:/dev/shm/ -v /dev/null/:/dev/null/ ubuntu2004:rdma /init_proc
orig_cont_id=`docker inspect ${orig_cont} | grep Id | awk -F '[" ]+' '{print $4}'`
new_cont_id=`docker inspect ${new_cont} | grep Id | awk -F '[" ]+' '{print $4}'`
old_init_pid=`docker inspect ${orig_cont} | grep \"Pid\" | awk -F '[", ]+' '{print $4}'`
new_init_pid=`docker inspect ${new_cont} | grep \"Pid\" | awk -F '[", ]+' '{print $4}'`

if [ -n "`ls /run/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id} 2> /dev/stdout > /dev/null`" ]; then
	docker_new=1
else
	docker_new=0
fi

./src/wbs_external/wbs ${old_init_pid} /dev/shm/restorerdma/
runc --root /var/run/docker/runtime-runc/moby/ --log /dev/shm/${orig_cont_id}.json --log-format json checkpoint \
					--migr-dst ${migr_dst} \
					--image-path /dev/shm/restorerdma/ --work-path /dev/shm/workpath/ ${orig_cont_id}

#cp /var/lib/docker/containers/${new_cont_id}/checkpoints/restorerdma/* /dev/shm/restorerdma/ -r

mkdir /dev/shm/predump_img
mkdir /dev/shm/restorerdma/fdiff
start=`date +"%s.%N"`
cp /dev/shm/restorerdma/* /dev/shm/predump_img/ -r
cp `docker inspect ${orig_cont} | grep Upper | awk -F '[:," ]+' '{print $3}'`/* /dev/shm/restorerdma/fdiff/ -r
cp /dev/shm/restorerdma/fdiff/* `docker inspect ${new_cont} | grep Upper | awk -F '[:," ]+' '{print $3}'`/ -r
end=`date +"%s.%N"`

if [ ${docker_new} -ne 0 ]; then
	./utils/fullrestore/rdma_fullrestore --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v2.task/moby/${new_cont_id}/log.json \
					--log-format json rdmarestore --image-path /dev/shm/restorerdma/ \
					--work-path /run/containerd/io.containerd.runtime.v2.task/moby/${new_cont_id}/work \
					--migr-dst ${migr_dst} \
					--detach --pid-file /run/containerd/io.containerd.runtime.v2.task/moby/${new_cont_id}/init.pid -no-subreaper \
					--bundle /run/containerd/io.containerd.runtime.v2.task/moby/${new_cont_id} ${new_cont_id} < /proc/${new_init_pid}/fd/0 > /proc/${new_init_pid}/fd/1 2> /proc/${new_init_pid}/fd/2
else
	./utils/fullrestore/rdma_fullrestore --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id}.json \
					--log-format json rdmarestore --image-path /dev/shm/restorerdma/ \
					--work-path /var/lib/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id} \
					--migr-dst ${migr_dst} \
					--detach --pid-file /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id}/init.pid -no-subreaper \
					--bundle /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id} ${new_cont_id} < /proc/${new_init_pid}/fd/0 > /proc/${new_init_pid}/fd/1 2> /proc/${new_init_pid}/fd/2
fi

mkdir /dev/shm/restorerdma/checkpoint1/

while [ -z "`ls /dev/shm/restore_*.log 2> /dev/null`" ]; do
	sleep 1
done

while [ -n "`ps -C criu | grep -v PID`" ]; do
	sleep 1
done

transfer_time=`echo "scale=3; ($end - $start) * 1000.0" | bc`
total_dump_raw=`cat /dev/shm/dump_*.log | tail -n 1 | awk -F '[()]+' '{print $2}'`
total_dump=`echo "scale=3; $total_dump_raw * 1000.0" | bc`
start_raw=`cat /dev/shm/dump_*.log | grep "dump RDMA" | awk -F '[()]+' '{print $2}'`
start=`echo "scale=3; $start_raw * 1000.0" | bc`
end_raw=`cat /dev/shm/dump_*.log | grep "Dump RDMA" | awk -F '[()]+' '{print $2}'`
end=`echo "scale=3; $end_raw * 1000.0" | bc`
dump_rdma=`echo "scale=3; $end - $start" | bc`
start_raw=`cat /dev/shm/restore_*.log | grep "Full restore start" | awk -F '[()]+' '{print $2}'`
start=`echo "scale=3; $start_raw * 1000.0" | bc`
end_raw=`cat /dev/shm/restore_*.log | tail -n 1 | awk -F '[()]+' '{print $2}'`
end=`echo "scale=3; $end_raw * 1000.0" | bc`
partial_restore=$start
full_restore_tmp=`echo "scale=3; $end - $start" | bc`
start_raw=`cat /dev/shm/restore_*.log | grep "pre-restore RDMA" | awk -F '[()]+' '{print $2}'`
start=`echo "scale=3; $start_raw * 1000.0" | bc`
end_raw=`cat /dev/shm/restore_*.log | grep "Pre-restore RDMA" | awk -F '[()]+' '{print $2}'`
end=`echo "scale=3; $end_raw * 1000.0" | bc`
prerestore_rdma=`echo "scale=3; $end - $start" | bc`
start_raw=`cat /dev/shm/restore_*.log | grep "Update RDMA metadata" | awk -F '[()]+' '{print $2}'`
start=`echo "scale=3; $start_raw * 1000.0" | bc`
end_raw=`cat /dev/shm/restore_*.log | grep "Full restore RDMA" | awk -F '[()]+' '{print $2}'`
end=`echo "scale=3; $end_raw * 1000.0" | bc`
post_rdma=`echo "scale=3; $end - $start" | bc`
restore_rdma=`echo "scale=3; ${prerestore_rdma} + ${post_rdma}" | bc`
full_restore=`echo "scale=3; ${full_restore_tmp} - ${restore_rdma}" | bc`

echo "DumpRDMA: ${dump_rdma} ms"
echo "DumpOthers: `echo \"scale=3; ${total_dump} - ${dump_rdma}\" | bc` ms"
echo "Transfer: ${transfer_time} ms"
echo "FullRestore: `echo \"scale=3; ${partial_restore} + ${full_restore}\" | bc` ms"
echo "RestoreRDMA: ${restore_rdma} ms"

cd /dev/shm/
rm *.json checkpoint_time *.log dump_img/ predump_img/ restorerdma/ workpath *.sock dump dumprdma -r
