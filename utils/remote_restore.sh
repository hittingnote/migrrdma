#!/bin/bash

cont_name=$1
migr_dst=$2
prestore_prog=$3

new_cont_id=`docker inspect ${cont_name} | grep Id | awk -F '[" ]+' '{print $4}'`
new_init_pid=`docker inspect ${cont_name} | grep \"Pid\" | awk -F '[", ]+' '{print $4}'`

if [ -n "`ls /run/containerd/io.containerd.runtime.v1.linux/moby/${orig_cont_id} 2> /dev/stdout > /dev/null`" ]; then
	docker_new=1
else
	docker_new=0
fi

if [ ${docker_new} -ne 0 ]; then
	if [ -z "${migr_dst}" ]; then
		runc --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v2.task/moby/${new_cont_id}/log.json \
						--log-format json restore --image-path /dev/shm/restorerdma/ \
						${new_cont_id}
	else
		${prestore_prog} --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v2.task/moby/${new_cont_id}/log.json \
						--log-format json rdmarestore --image-path /dev/shm/restorerdma/ \
						--work-path /run/containerd/io.containerd.runtime.v2.task/moby/${new_cont_id}/work \
						--migr-dst ${migr_dst} \
						--detach --pid-file /run/containerd/io.containerd.runtime.v2.task/moby/${new_cont_id}/init.pid -no-subreaper \
						--bundle /run/containerd/io.containerd.runtime.v2.task/moby/${new_cont_id} ${new_cont_id} < /proc/${new_init_pid}/fd/0 > /proc/${new_init_pid}/fd/1 2> /proc/${new_init_pid}/fd/2
	fi
else
	if [ -z "${migr_dst}" ]; then
		runc --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id}.json \
						--log-format json restore --image-path /dev/shm/restorerdma/ \
						${new_cont_id}
	else
		${prestore_prog} --root /var/run/docker/runtime-runc/moby --log /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id}.json \
						--log-format json rdmarestore --image-path /dev/shm/restorerdma/ \
						--work-path /var/lib/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id} \
						--migr-dst ${migr_dst} \
						--detach --pid-file /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id}/init.pid -no-subreaper \
						--bundle /run/containerd/io.containerd.runtime.v1.linux/moby/${new_cont_id} ${new_cont_id} < /proc/${new_init_pid}/fd/0 > /proc/${new_init_pid}/fd/1 2> /proc/${new_init_pid}/fd/2
	fi
fi
