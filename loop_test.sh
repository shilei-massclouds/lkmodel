#!/bin/sh

for i in $(seq 1 3)
do
    make run I=/btp/sbin/runltp
done
