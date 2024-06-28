#!/bin/sh

riscv64-linux-gnu-gcc -static ./main1.c -o hello1
riscv64-linux-gnu-strip ./hello1
riscv64-linux-gnu-gcc -static ./main2.c -o hello2
riscv64-linux-gnu-strip ./hello2

# There're two apps.
printf "00000002" > ./package

ls -l ./hello1 | awk '{printf "%08x", $5}' >> ./package
cat ./hello1 >> ./package

ls -l ./hello2 | awk '{printf "%08x", $5}' >> ./package
cat ./hello2 >> ./package

dd if=/dev/zero of=./apps.bin bs=1M count=32
dd if=./package of=./apps.bin conv=notrunc

mv ./apps.bin ../apps.bin
