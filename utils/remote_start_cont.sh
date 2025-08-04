#!/bin/bash

cont_name=$1

docker run -d --name ${cont_name} --hostname ${cont_name} --ulimit nofile=32768:32768 --net=host --device=/dev/infiniband/ --cap-add=ALL --privileged -v /dev/shm/:/dev/shm/ -v /dev/null/:/dev/null/ ubuntu2004:rdma /init_proc
