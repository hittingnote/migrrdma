#!/bin/bash

cd src/mlnx-ofed-kernel-5.4/
./configure $(./ofed_scripts/dkms_ofed `uname -r` /lib/modules/`uname -r`/build/ get-config) --with-njobs=8
make -j24

cd ../rdma-core-54mlnx1/
sed -i "34s/.*/#define IBACM_IBACME_SERVER_PATH IBACM_SERVER_BASE/" buildlib/config.h.in
sed -i "35s/.*/#define IBACM_SERVER_PATH \"ibacm.sock\"/" buildlib/config.h.in
./build.sh

cd ../criu-3.18/
make -j24

cd ../runc
make

