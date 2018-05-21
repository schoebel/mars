#!/bin/bash

picturetype="${picturetype:-pdfcairo}" # [ps|jpeg|gif|...]
pictureoptions="${pictureoptions:=small size 800,400}"

gnuplot <<EOF
set term $picturetype $pictureoptions;
set output "Capacity-BitRate-Comparison.pdf";
set title "Long-Term Development of HDD Capacity vs Network Bandwidth";
set xlabel "Year";
set ylabel "Capacity in [MByte], BitRates in [MBit/s]";
set logscale y;
plot "HDD.capacity" with lines, "Ethernet.rates" with lines, "Infiniband.rates" with lines;
EOF
