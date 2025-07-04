#!/bin/bash

make

wget https://content.mellanox.com/ofed/MLNX_OFED-5.4-1.0.3.0/MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64.tgz
wget http://github.com/checkpoint-restore/criu/archive/v3.18/criu-3.18.tar.gz
tar -zxf MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64.tgz
cd MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64/src/
tar -zxf MLNX_OFED_SRC-5.4-1.0.3.0.tgz
cd MLNX_OFED_SRC-5.4-1.0.3.0/SOURCES/
tar -zxf mlnx-ofed-kernel_5.4.orig.tar.gz
tar -zxf rdma-core_54mlnx1.orig.tar.gz
cd mlnx-ofed-kernel-5.4
patch -p1 < ../../../../../../src/diff_mlnx-ofed-kernel-5.4.patch
cd ..
cd rdma-core-54mlnx1
patch -p1 < ../../../../../../src/diff_rdma-core-54mlnx1.patch
patch -p1 < ../../../../../src/diff_rdma-core-54mlnx1.patch

