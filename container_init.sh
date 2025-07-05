#!/bin/bash

docker run -d --name test --hostname test --net=host --device=/dev/infiniband/ --cap-add=ALL --privileged -e "DEBIAN_FRONTEND=noninteractive" -v /dev/shm/:/dev/shm/ -v /dev/null/:/dev/null/ ubuntu:20.04 /bin/sh -c 'while [ true ]; do sleep 10; done'

docker cp MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64 test:/
docker cp sources.list test:/etc/apt/
docker cp init_proc/init_proc test:/
docker cp fork/fork_perftest test:/

docker exec test /bin/sh -c 'apt-get update; \
	apt-get -y install iputils-ping net-tools build-essential wget git vim \
	cmake python pkg-config libnl-route-3-dev automake autoconf libtool \
	libpci-dev pciutils; \
	cd MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64/src/MLNX_OFED_SRC-5.4-1.0.3.0/SOURCES/rdma-core-54mlnx1; \
	sed -i "34s/.*/#define IBACM_IBACME_SERVER_PATH IBACM_SERVER_BASE/" buildlib/config.h.in; \
	sed -i "35s/.*/#define IBACM_SERVER_PATH \"ibacm.sock\"/" buildlib/config.h.in; \
	./build.sh; \
	cp build/lib/* /usr/lib/ -r; \
	cp -L build/include/infiniband build/include/rdma /usr/include/ -r; \
	cd ..; \
	tar -zxf perftest_4.5.orig.tar.gz; \
	cd perftest-4.5; \
	./autogen.sh; \
	./configure; \
	make; \
	make install'

docker commit test ubuntu2004:rdma
docker rm -f test

