#!/bin/sh

for i in $(seq 1 50)
do
    make run I=/btp/sbin/runltp
done
