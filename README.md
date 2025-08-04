# MigrRDMA

## Overview

MigrRDMA is the first software-based RDMA live migration solution without modifying the RNIC.
This repository releases our implementation prototype.
The MigrRDMA's components are in [src/](./src).
The scripts and applications supporting the live migration workflow are in [utils/](./utils).
Our implementation is based on MLNX OFED Driver 5.4,
CRIU 3.18, and [runc](https://github.com/opencontainers/runc/tree/8fc5be4e60246eb9f7c50e9150f9b1d21f835f8a).
To figure out what exact change we made to each component,
you can click the commit message behind each of their directories.

MigrRDMA was accepted in SIGCOMM'25.
Interested readers may refer to [our paper](./docs/migrrdma_paper.pdf).

## Prerequisite

We have finished building MigrRDMA on Ubuntu 20.04 and 22.04.
The MigrRDMA driver has been compiled successfully on Linux kernel 5.8 and 5.12, and failed on kernel 5.4 and 5.15.
Thus, we recommend re-constructing MigrRDMA on one of the Linux kernels from 5.8 to 5.12.

Before building MigrRDMA, please install the following packages. Note that executing the following commands is enough for Ubuntu 22.04. If you do re-construction on Ubuntu 20.04, please install other packages if they are shown in the error messages.

```bash
$ apt-get -y install cmake asciidoc python3 python3-pip automake autoconf libpci-dev
$ apt-get -y install $(apt-cache search pkgconfig | awk '{print $1}' | grep -v libyang2)
$ apt-get -y install $(apt-cache search libnl | awk '{print $1}')
$ apt-get -y install $(apt-cache search protobuf |awk '{print $1}' | grep -v "protoc-gen-go")
$ apt-get -y install $(apt-cache search libnet | awk '{print $1}' | grep -v "libnetpbm")
$ apt-get -y install $(apt-cache search libcap | awk '{print $1}')
$ wget https://go.dev/dl/go1.20.linux-amd64.tar.gz
$ tar -zxf go1.20.linux-amd64.tar.gz
$ cd go
$ echo "export GOPATH=$(pwd)" >> ~/.bashrc
$ echo "export PATH=\${GOPATH}/bin:\${PATH}" >> ~/.bashrc
$ source ~/.bashrc
```

`cmake`, `pkgconfig`, and `libnl` are for RDMA library.
`protobuf`, `libnet`, `asciidoc`, and `libcap` are for CRIU.
`go1.20` is for runc.

Besides, we also need to install `docker-ce`.
Currently, our prototype integrates well with Docker 19.03 and 20.10.
Please execute the following commands to install `docker-ce` (you can refer to [this Docker installation tutorial](https://docs.docker.com/engine/install/ubuntu/)):

```Bash
$ sudo apt-get update
$ sudo apt-get -y install ca-certificates curl
$ sudo install -m 0755 -d /etc/apt/keyrings
$ sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
$ sudo chmod a+r /etc/apt/keyrings/docker.asc
$ echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
$ sudo apt-get update
$ sudo apt-get -y install docker-ce=5:20.10.13~3-0~ubuntu-jammy
```

You can execute `apt-cache madison docker-ce` to check all the available versions of `docker-ce` on your local server,
and replace the `5:20.10.13~3-0~ubuntu-jammy` part with what you prefer.

## Build and Install

Run the following commands to build a container image, compile and install MigrRDMA.

```Bash
$ ./container_init.sh
$ ./build.sh
$ make
```

The installation of MigrRDMA driver is not permanently effective.
After reboot, the server loads the regular RDMA driver by default.
Thus, you need to re-execute `./build.sh` to install the MigrRDMA driver again.

To verify whether all the components are installed correctly,
you can first run the following commands:

```Bash
$ show_gids
$ ls /proc/rdma
```

`show_gids` lists all the information of RDMA NICs. If all the information are shown, that means the RDMA driver works.

MigrRDMA maintains the RDMA information in `procfs`. If you see `/proc/rdma` in your system, that means you have installed MigrRDMA's driver, rather than the regular one.

To test whether the regular `perftest` runs correctly, you can start `perftest` with the following settings:

```Bash
$ ib_send_bw -d [DEV] --use_old_post_send -a
```

Please note that our implementation only covers the standard verbs APIs. Thus, `--use_old_post_send` option is necessary here.

## Live Migration Demo

After all the verification is done, you can run a simple demo for RDMA live migration.

Suppose a sender is issuing two-sided verbs to a receiver, and an operator wants to migrate the sender.
You can start the receiver by executing:

```Bash
$ ib_send_bw -d [DEV] --use_old_post_send --run_infinitely -s 4096 -s 64 -r 64
```

Then, start the sender by executing:

```Bash
$ ./rdma_migr_demo.sh ib_send_bw -d [DEV] --use_old_post_send --run_infinitely -s 4096 -s 64 -r 64 [IP_ADDR]
```

The `rdma_migr_demo.sh` script starts a container running `ib_send_bw`, then starts live migration after a while.

You can change to migrate the receiver.
Besides, settings of `perftest` other than the one shown in the demo (including
varying RDMA operations, queue depths, message sizes, w/wo CQ events, SRQs, etc.) can also work.
