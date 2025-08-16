## Artifact Evaluation

We select some representative experiments for artifact evaluation.
All the evaluations are based on the script `eval_basic.sh`.
The command-line format of the script is as follows:

```Bash
$ ./eval_basic.sh [with or without pre-setup] [migrate sender or receiver] [IP address of partner] [IP address of migration destination] [ibdev name] [brief perftest command]
```

For example, if you migrate the sender under the pre-setup case, execute:

```Bash
$ sudo ./eval_basic.sh with_pre_setup send [partner] [migration destination] [ibdev name] ib_send_bw -s 65536 -r 64 -t 64
```

If you migrate the receiver under the withou-pre-setup case, execute:

```Bash
$ sudo ./eval_basic.sh wo_pre_setup recv [partner] [migration destination] [ibdev name] ib_send_bw -s 65536 -r 64 -t 64
```

For both examples, `ib_send_bw -s 65536 -r 64 -t 64` is a brief options to run the perftest.
`ib_send_bw` is a perftest program that starts bandwidth test where the sender issues SEND operations to the receiver.
`-s` represents the message size, `-t` and `-r` denote the depth of the send and receive queue of each QP, respectively.
the `eval_basic.sh` script will embed all the rest options to the brief options.

Inside each directory is the scripts to reproduce the evaluations and plot the results.
Please read the README inside to reproduce each of them.

[Eval 1: Benefit of RDMA Pre-setup](01_pre_setup_benefit)

[Eval 2: Overhead of Wait-before-stop](02_wbs_overhead)
