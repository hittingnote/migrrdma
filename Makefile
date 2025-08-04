mlnx_drv_src := $(shell find src/mlnx-ofed-kernel-5.4/ -name *.c) $(shell find src/mlnx-ofed-kernel-5.4/ -name *.h)
rdma_core_src := $(shell find src/rdma-core-54mlnx1/ -name *.c) $(shell find src/rdma-core-54mlnx1/ -name *.h)
criu_src := $(shell find src/rdma-core-54mlnx1/ -name *.h) $(shell find src/criu-3.18/ -name *.c) $(shell find src/criu-3.18/ -name *.h)
runc_src := $(shell find src/runc -name *.go)
utils_tgt := src/wbs_external src/migrrdma_daemon utils/prerestore utils/fullrestore

define get_mlx5_core_netconf
	ip addr show | while read LINE; do												\
		if [ -n "`echo $$LINE | grep mtu`" ]; then										\
			netif_name=`echo $$LINE | awk -F '[: ]+' '{print $$2}'`;							\
		elif [ -n "`echo $$LINE | grep inet | grep -v inet6`" ]; then								\
			ipaddr=`echo $$LINE | awk '{print $$2}'`;									\
			businfo=`ethtool -i $${netif_name} 2> /dev/null | grep bus | awk '{print $$2}'`;				\
			if [ -n "$${businfo}" ] && [ -n "`ethtool -i $${netif_name} 2>/dev/null | grep mlx5_core`" ]; then		\
				echo $$(echo $${businfo} | awk -F '[:]+' '{printf "%s:%s\n",$$2,$$3}') $${netif_name} $${ipaddr};	\
			fi;														\
		fi;															\
	done
endef

define get_mlx5_core_netconf_v2
	ip addr show | while read LINE; do												\
		if [ -n "`echo $$LINE | grep mtu`" ]; then										\
			netif_name=`echo $$LINE | awk -F '[: ]+' '{print $$2}'`;							\
			businfo=`ethtool -i $${netif_name} 2> /dev/null | grep bus | awk '{print $$2}'`;				\
			if [ -n "$${businfo}" ] && [ -n "`ethtool -i $${netif_name} 2>/dev/null | grep mlx5_core`" ]; then		\
				echo $$(echo $${businfo} | awk -F '[:]+' '{printf "%s:%s\n",$$2,$$3}') $${netif_name};			\
			fi;														\
		fi;															\
	done
endef

all: .mlnx_drv .rdma_core .criu .runc .cc_utils

install: .mlnx_drv_install .rdma_core_install .criu_install .runc_install .mlnx_utils .mlnx_utils_install

mlnx_install: .mlnx_drv_install

.mlnx_drv: $(mlnx_drv_src)
	@cd src/mlnx-ofed-kernel-5.4/; \
		./configure $$(./ofed_scripts/dkms_ofed `uname -r` /lib/modules/`uname -r`/build/ get-config) --with-njobs=8; \
		make -j24
	@touch $@

.rdma_core: $(rdma_core_src)
	@cd src/rdma-core-54mlnx1/; \
		sed -i "34s/.*/#define IBACM_IBACME_SERVER_PATH IBACM_SERVER_BASE/" buildlib/config.h.in; \
		sed -i "35s/.*/#define IBACM_SERVER_PATH \"ibacm.sock\"/" buildlib/config.h.in; \
		./build.sh
	@touch $@

.criu: $(criu_src) .rdma_core
	@cd src/criu-3.18/; sed -i 's/-Werror//g' Makefile; make -j24
	@touch $@

.runc: $(runc_src)
	@cd src/runc/; \
		make
	@touch $@

.mlnx_drv_install: .mlnx_drv
	@./src/mlnx-ofed-kernel-5.4/load.sh
	@touch $@

.rdma_core_install: .rdma_core
	@cd src/rdma-core-54mlnx1;	\
		cp build/lib/* /usr/lib/x86_64-linux-gnu/ -r;		\
		cp -L build/include/infiniband build/include/rdma /usr/include/ -r
	@touch $@

.criu_install: .criu
	@cd src/criu-3.18/;		\
		make install
	@touch $@

.runc_install: .runc
	@cd src/runc/;			\
		make install
	@touch $@

.cc_utils: .rdma_core
	@for i in $(utils_tgt); do		\
		make -C $$i;			\
		if [ $$? -ne 0 ]; then		\
			exit $$?;		\
		fi;				\
	done

.mlnx_utils: .rdma_core
	@wget https://content.mellanox.com/ofed/MLNX_OFED-5.4-1.0.3.0/MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64.tgz
	@tar -zxf MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64.tgz
	@cd MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64/src/;				\
		tar -zxf MLNX_OFED_SRC-5.4-1.0.3.0.tgz;						\
		cd MLNX_OFED_SRC-5.4-1.0.3.0/SOURCES/;						\
		tar -zxf perftest_4.5.orig.tar.gz;						\
		cd perftest-4.5;								\
		./autogen.sh;									\
		./configure;									\
		make -j24
	@touch $@

.mlnx_utils_install:
	@cd MLNX_OFED_LINUX-5.4-1.0.3.0-ubuntu20.04-x86_64/src/MLNX_OFED_SRC-5.4-1.0.3.0/SOURCES/perftest-4.5;		\
		make install;												\
		cd ..;													\
		tar -zxf mlnx-tools_5.2.0.orig.tar.gz;									\
		cd mlnx-tools-5.2.0;											\
		make install || true
	@touch $@

