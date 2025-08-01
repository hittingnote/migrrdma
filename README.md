# MigrRDMA: Software-based Live Migration for RDMA

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

## Build and Install

Run `./build.sh` script to install all the components in `src/`.

```Bash
$ ./build.sh
```

To verify that all the components are installed correctly,
you can run `show_gids`:

```Bash
$ show_gids
DEV     PORT    INDEX   GID                                     IPv4            VER     DEV
---     ----    -----   ---                                     ------------    ---     ---
[All the info]
```

Then, run `perftest` with the following settings:

```Bash
$ ib_send_bw -d [DEV] --use_old_post_send -a
```

Please note that our implementation only covers the standard verbs APIs. Thus, `--use_old_post_send` option is necessary here.
