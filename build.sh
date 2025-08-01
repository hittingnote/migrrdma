#!/bin/bash

get_mlx5_core_netconf() {
	ip addr show | while read LINE; do
		if [ -n "`echo $LINE | grep mtu`" ]; then
			netif_name=`echo $LINE | awk -F '[: ]+' '{print $2}'`
		elif [ -n "`echo $LINE | grep inet | grep -v inet6`" ]; then
			ipaddr=`echo $LINE | awk '{print $2}'`
			businfo=`ethtool -i ${netif_name} 2> /dev/null | grep bus | awk '{print $2}'`
			if [ -n "${businfo}" ] && [ -n "`ethtool -i ${netif_name} 2>/dev/null | grep mlx5_core`" ]; then
				echo $(echo ${businfo} | awk -F '[:]+' '{printf "%s:%s\n",$2,$3}') ${netif_name} ${ipaddr}
			fi
		fi
	done
}

get_mlx5_core_netconf_v2() {
ip addr show | while read LINE; do
	if [ -n "`echo $LINE | grep mtu`" ]; then
		netif_name=`echo $LINE | awk -F '[: ]+' '{print $2}'`
		businfo=`ethtool -i ${netif_name} 2> /dev/null | grep bus | awk '{print $2}'`
		if [ -n "${businfo}" ] && [ -n "`ethtool -i ${netif_name} 2>/dev/null | grep mlx5_core`" ]; then
			echo $(echo ${businfo} | awk -F '[:]+' '{printf "%s:%s\n",$2,$3}') ${netif_name}
		fi
	fi
done
}

cd src/mlnx-ofed-kernel-5.4/
./configure $(./ofed_scripts/dkms_ofed `uname -r` /lib/modules/`uname -r`/build/ get-config) --with-njobs=8
make -j24
sudo make install

get_mlx5_core_netconf > oldcfg.txt
for i in {1..5}; do
	for j in $(find . -name *.ko); do
		sudo rmmod $j &> /dev/null
	done
done

for i in {1..5}; do
	for j in $(find . -name *.ko); do
		sudo insmod $j &> /dev/null
	done
done
sudo modprobe mlx5_core
sleep 3
get_mlx5_core_netconf_v2 > newcfg.txt

cat oldcfg.txt
echo "--------------------------------"
cat newcfg.txt
echo "--------------------------------"

cat oldcfg.txt | while read LINE; do
	item=$(cat newcfg.txt | grep `echo $LINE | awk '{print $1}'`)
	sudo ip link set `echo ${item} | awk '{print $2}'` up
	echo sudo ip link set `echo ${item} | awk '{print $2}'` up
	sudo ip addr add `echo ${LINE} | awk '{print $3}'` dev  `echo ${item} | awk '{print $2}'`
	echo sudo ip addr add `echo ${LINE} | awk '{print $3}'` dev  `echo ${item} | awk '{print $2}'`
done

rm oldcfg.txt newcfg.txt

for i in {1..5}; do
	for j in $(find . -name *.ko); do
		sudo insmod $j &> /dev/null
	done
done

cd ../rdma-core-54mlnx1/
sed -i "34s/.*/#define IBACM_IBACME_SERVER_PATH IBACM_SERVER_BASE/" buildlib/config.h.in
sed -i "35s/.*/#define IBACM_SERVER_PATH \"ibacm.sock\"/" buildlib/config.h.in
./build.sh
sudo cp build/lib/* /usr/lib/x86_64-linux-gnu/ -r
sudo cp -L build/include/infiniband build/include/rdma /usr/include/ -r

cd ../criu-3.18/
sed -i 's/-Werror//g' Makefile
make -j24
sudo make install

cd ../runc
make
sudo make install

cd ../..
wget https://content.mellanox.com/ofed/MLNX_OFED-5.4-1.0.3.0/MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64.tgz
tar -zxf MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64.tgz
cd MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64/src/
tar -zxf MLNX_OFED_SRC-5.4-1.0.3.0.tgz
cd MLNX_OFED_SRC-5.4-1.0.3.0/SOURCES/
tar -zxf perftest_4.5.orig.tar.gz
cd perftest-4.5
./autogen.sh
./configure
make -j24
sudo make install

cd ..
tar -zxf mlnx-tools_5.2.0.orig.tar.gz
cd mlnx-tools-5.2.0/
sudo make install

