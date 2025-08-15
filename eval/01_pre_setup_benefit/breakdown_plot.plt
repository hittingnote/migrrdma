set terminal wxt enhanced font "arial,19" fontscale 1.2 size 1020, 580
# set output 'histograms.3.png'
set boxwidth 0.9 absolute
set style fill   solid 1.00 border lt -1
set key left top vertical Right noreverse noenhanced autotitle nobox
unset key
set style histogram rowstacked gap 2.5 title textcolor lt -1
set datafile missing '-'
set style data histograms
set xtics border in scale 0,0 nomirror rotate by -30  autojustify
set xtics  norangelimit 
set xtics   ()
set ytics ()
set y2tics ()
set grid
#set title "US immigration from Northern Europe\n(same plot with larger gap between clusters)" 
#set xrange [ * : * ] noreverse writeback
#set x2range [ * : * ] noreverse writeback
set yrange [ 0.0 : 100 ] noreverse writeback
set y2range [ 0.0 : 100 ] noreverse writeback
#set zrange [ * : * ] noreverse writeback
#set cbrange [ * : * ] noreverse writeback
#set rrange [ * : * ] noreverse writeback
NO_ANIMATION = 1
## Last datafile plotted: "immigration.dat"
set xlabel "# of QP"
set ylabel "Breakdown (%)"
set y2label "Breakdown (%)"
set for [i=0:100:20] ytics add (sprintf("%d", i) i)
set for [i=0:100:20] y2tics add (sprintf("%d", i) i)
#set format y "%d"
#set format y2 "%d"
set xrange [ -1.8 : 14.8 ]

set xtics ()

set for [i=0:4] xtics add (sprintf("%d", 2**(3*i)) 3*i+0.5)

plot 'breakdown_data.txt' using ($3*100) ti "DumpRDMA" fs pattern 1 lc "dark-blue", \
		'' using ($4*100) ti "DumpOthers" fs pattern 2 lc "dark-blue", \
		'' using ($5*100) ti "CompressAndTransfer" fs pattern 4 lc "dark-blue", \
		'' using (($6+$8)*100) ti "FullRestore" fs pattern 7 lc "dark-blue", \
		'' using ($7*100) ti "RestoreRDMA" fs pattern 6 lc "dark-blue", \
		\
		'' using ($10*100) ti "DumpOthers" fs pattern 1 lc "sandybrown", \
		'' using ($11*100) ti "DumpOthers" fs pattern 2 lc "sandybrown", \
		'' using ($12*100) ti "CompressAndTransfer" fs pattern 4 lc "sandybrown", \
		'' using ($14*100) ti "RestoreRDMA" fs pattern 6 lc "sandybrown", \
		'' using (($13+$15)*100) ti "FullRestore" fs pattern 7 lc "sandybrown", \
		'' using ($16*100) ti "Optimized" fs pattern 0 lc "sandybrown"

