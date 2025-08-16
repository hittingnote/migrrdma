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

In the extended `perftest`, the client connects to multiple servers and issues verbs operations.
Thus, you need to type the following commands:

On the servers:

```Bash
$ for i in {1..4}; do ib_send_bw -d [mlnx_dev] --use_old_post_send --run_infinitely -p `expr 12345 + $i` [other options] & done
```

Note: `--run_infinitely` is necessary here because the extended `perftest` only supports this option.
Besides, you also need to ensure the port number (`-p` option) is consecutive.

On the client:

```Bash
ib_send_bw -d [mlnx_dev] --use_old_post_send --run_infinitely -p 12346 [other options] `for i in {1..4}; do echo "${server_ip}"; done`
```

Note: You need to specify the IP addresses of all the servers. If the servers reside on a single node, just repeat the IP address of the node as many times as the number of servers (in this example, we need to repeat 4 times).

If you want many senders to issue verbs operations to one receiver, just add `--reversed` flag in both commands to reverse the traffic.
