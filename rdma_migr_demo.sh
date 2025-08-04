#!/bin/bash

pre_setup=$1
migr_dst=$2

shift 2

if [ -z "$(show_gids | grep ${migr_dst})" ]; then
	remote="_remote"
fi

echo "Now start ${pre_setup} case"

docker run -d --name test --hostname test --ulimit nofile=32768:32768 --net=host --device=/dev/infiniband/ --cap-add=ALL --privileged -v /dev/shm/:/dev/shm/ -v /dev/null/:/dev/null/ ubuntu2004:rdma $@

sleep 30

utils/migrrdma_${pre_setup}${remote}.sh test test1 0 ${migr_dst}
