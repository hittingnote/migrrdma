#!/bin/bash

docker run -d --name test --hostname test --ulimit nofile=32768:32768 --net=host --device=/dev/infiniband/ --cap-add=ALL --privileged -v /dev/shm/:/dev/shm/ -v /dev/null/:/dev/null/ ubuntu2004:rdma $@

sleep 30

utils/migrrdma_with_pre_setup.sh test test1 0 192.168.2.15

