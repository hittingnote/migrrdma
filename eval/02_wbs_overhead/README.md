### Overhead of Wait-before-stop

Execute `script.sh`.

```Bash
$ ./script.sh > raw.data
```

Then, execute `plot.plt` using `gnuplot` to plot the results.

`script.sh` just gives an example of evaluating the overhead with the varying message size.
You can change the script to evaluate under varying other factors.

#### Add Many-to-one Support to `Perftest`

To evaluate the overhead of wait-before-stop under the varying numbers of partners, we need to add many-to-one support to `perftest`.
This is done by one of the existing repository:
[https://github.com/chengwx1992/perftest](https://github.com/chengwx1992/perftest).
Here, we just copy the [`many-to-one`](https://github.com/chengwx1992/perftest/tree/many_to_one) branch in our directory.
You can click the commit message behind the perftest directory to see what exact change was made.

##### Compile

```Bash
$ cd perftest
$ ./autogen.sh
$ ./configure
$ make
```

Note: Do not execute `sudo make install` to overwrite the original binary of `perftest`.

##### Run

On the servers (Execute the original binary):

```Bash
$ for i in {1..4}; do ib_send_bw -d [mlnx_dev] --use_old_post_send --run_infinitely -p `expr 12345 + $i` [other options] -D [duration] & done
```

Note: `--run_infinitely` is necessary here because the extended `perftest` only supports this option.
Besides, you also need to ensure the port number (`-p` option) is consecutive.

On the client (Execute the binary we've just compiled):

```Bash
$ cd perftest
$ ./ib_send_bw -d [mlnx_dev] --use_old_post_send --run_infinitely -p 12346 [other options] -D [duration] `for i in {1..4}; do echo "${server_ip}"; done`
```

Note:
* You need to specify the IP addresses of all the servers. If the servers reside on a single node, just repeat the IP address of the node as many times as the number of servers (in this example, we need to repeat 4 times).
* The modified `perftest` does not exit elegantly. You need to use `Ctrl+C` or `pkill -9 ib_send_bw` to kill them.
* To run RDMA live migration with the varying numbers of partners, we recommend modifying [`container_init.sh`](../../container_init.sh) to build the modified `perftest` inside the container, then rebuild the container image. An example is given by [./container_init.patch](./container_init.patch).
You can run the following commands:  
```Bash
$ cd [root of the repository]
$ patch -p1 < eval/02_wbs_overhead/container_init.patch
```  
To reverse the modification, run the following commands:  
```Bash
$ cd [root of the repository]
$ patch -p1 -R < eval/02_wbs_overhead/container_init.patch
```
* If you want many senders to issue verbs operations to one receiver, just add `--reversed` flag in both commands to reverse the traffic.
