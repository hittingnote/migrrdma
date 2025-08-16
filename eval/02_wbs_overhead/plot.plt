set terminal wxt enhanced font "arial,19" fontscale 1.2 size 1200, 630 
# set output 'histograms.3.png'
set boxwidth 0.7 absolute
set style fill   solid 1.00 border lt -1
set key left top vertical Right noreverse noenhanced autotitle nobox
set key off
set style histogram rowstacked gap 2
set datafile missing '-'
set style data histograms
#set xtics border in scale 0,0 nomirror rotate by -30 autojustify offset -1.3
set xtics  norangelimit 
set xtics   ()
set grid
#set title "US immigration from Northern Europe\n(same plot with larger gap between clusters)" 
#set xrange [ * : * ] noreverse writeback
#set x2range [ * : * ] noreverse writeback
set xrange [-1.3 : 9.3]
set yrange [ 0.00000 : 300 ] noreverse writeback
set y2range [ 0 : 300 ]
#set y2range [ * : * ] noreverse writeback
#set zrange [ * : * ] noreverse writeback
#set cbrange [ * : * ] noreverse writeback
#set rrange [ * : * ] noreverse writeback
NO_ANIMATION = 1
## Last datafile plotted: "immigration.dat"
set ytics ()
set for [i=0:300:50] ytics add (sprintf("%d", i) i)
set y2tics ()
set for [i=0:300:50] y2tics add (sprintf("%d", i) i)
set xlabel "Message Size"
set ylabel "Elapsed Time (ms)"
set y2label "Elapsed Time (ms)"

plot 'raw.data' using ($3):xtic(1) notitle fs pattern 4 lc "dark-blue", \
	'' using ($2) notitle fs pattern 5 lc "sandybrown",
