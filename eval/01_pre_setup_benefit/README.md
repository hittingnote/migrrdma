### Benefit of RDMA Pre-setup

Execute `script.sh`.

```Bash
$ ./script.sh > raw_data.txt
```

Then, generate the breakdown data.

```Bash
$ ./breakdown_gen.sh raw_data.txt > breakdown_data.txt
```

Finally, use `blackout_time.plt` and `breakdown_plot.plt` to plot them.
You need to install `gnuplot` first before running the `.plt`.
