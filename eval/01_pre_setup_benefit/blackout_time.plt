set terminal wxt enhanced font "arial,19" fontscale 1.2 size 1020, 580
# set output 'histograms.3.png'
set boxwidth 0.9 absolute
set style fill   solid 1.00 border lt -1
set key left top vertical Right noreverse noenhanced autotitle nobox
unset key
set style histogram gap 1 title textcolor lt -1
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
set yrange [ 0.07 : 10 ] noreverse writeback
set y2range [ 0.07 : 10 ] noreverse writeback
#set zrange [ * : * ] noreverse writeback
#set cbrange [ * : * ] noreverse writeback
#set rrange [ * : * ] noreverse writeback
NO_ANIMATION = 1
## Last datafile plotted: "immigration.dat"
set xlabel "# of QP"
set ylabel "Blackout Time (s)"
set y2label "Blackout Time (s)"
set for [i=8:9] ytics add ("" 0.01*i 1)
set for [i=8:9] y2tics add ("" 0.01*i 1)
set ytics add ("0.1" 0.1)
set y2tics add ("0.1" 0.1)
set for [i=2:9] ytics add ("" 0.1*i 1)
set for [i=2:9] y2tics add ("" 0.1*i 1)
set ytics add ("1" 1)
set y2tics add ("1" 1)
set for [i=2:9] ytics add ("" 1*i 1)
set for [i=2:9] y2tics add ("" 1*i 1)
set ytics add ("10" 10)
set y2tics add ("10" 10)
#set format y "%d"
#set format y2 "%d"
set xrange [ -0.8 : 4.8 ]

set xtics ()

set logscale y
set logscale y2

set for [i=0:4] xtics add (sprintf("%d", 2**(3*i)) i)

plot 'raw_data.txt' using (($3+$4+$5+$6+$7+$8)/1000) ti "DumpRDMA" lc "dark-blue", \
		'' using (($10+$11+$12+$13+$14+$15)/1000) ti "DumpOthers" lc "sandybrown",


