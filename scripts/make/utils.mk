# Utility definitions and functions

GREEN_C := \033[92;1m
CYAN_C := \033[96;1m
YELLOW_C := \033[93;1m
GRAY_C := \033[90m
WHITE_C := \033[37m
END_C := \033[0m

define run_cmd
  @printf '$(WHITE_C)$(1)$(END_C) $(GRAY_C)$(2)$(END_C)\n'
  @$(1) $(2)
endef

define make_disk_image_fat32
  @printf "    $(GREEN_C)Creating$(END_C) FAT32 disk image \"$(1)\" ...\n"
  @dd if=/dev/zero of=$(1) bs=1M count=128
  @mkfs.fat -F 32 $(1)
endef

define make_disk_image
  $(if $(filter $(1),fat32), $(call make_disk_image_fat32,$(2)))
endef

define build_linux_image
  @mkdir -p ./mnt
  @sudo mount $(1) ./mnt
  @sudo mkdir -p ./mnt/lib
  @sudo mkdir -p ./mnt/sbin
  @sudo mkdir -p ./mnt/testcases
  @sudo cp ./payload/ld-linux-riscv64-lp64d.so.1 ./mnt/lib/
  @sudo cp ./payload/libc.so.6 ./mnt/lib/
  @sudo cp ./payload/init ./mnt/sbin/init
  -@sudo cp ./payload/testcases/* ./mnt/testcases/
  ls -l ./mnt/lib
  ls -l ./mnt/testcases
  @sudo umount ./mnt
  @rm -rf mnt
endef

define riscv64_install_apps
  @mkdir -p ./mnt
  @sudo mount $(1) ./mnt
  @sudo mkdir -p ./mnt/lib
  @sudo mkdir -p ./mnt/testcases
  @sudo mkdir -p ./mnt/opt
  @sudo mkdir -p ./mnt/etc
  @sudo mkdir -p ./mnt/usr/bin
  @sudo cp /usr/riscv64-linux-gnu/lib/ld-linux-riscv64-lp64d.so.1 ./mnt/lib/
  @sudo cp /usr/riscv64-linux-gnu/lib/libc.so.6 ./mnt/lib/
  @sudo cp /usr/riscv64-linux-gnu/lib/libm.so.6 ./mnt/lib/
  @sudo cp /usr/riscv64-linux-gnu/lib/libresolv.so.2 ./mnt/lib/
  @sudo cp -r ./btp/build/riscv64/sbin ./mnt/
  @sudo cp -r ./btp/etc ./mnt/
  @sudo cp ./btp/syscalls ./mnt/opt/
  @sudo cp ./btp/usr/bin/sh ./mnt/usr/bin/
  -@sudo cp -f $(LTP)/build_riscv64/testcases/bin/mmap[[:digit:]]* ./mnt/testcases/
  ls -l ./mnt/lib
  ls -l ./mnt/sbin
  ls -l ./mnt/testcases
  ls -l ./mnt/opt
  @sudo umount ./mnt
  @rm -rf mnt
endef

define x86_64_install_apps
  @mkdir -p ./mnt
  @sudo mount $(1) ./mnt
  @sudo mkdir -p ./mnt/lib
  @sudo mkdir -p ./mnt/lib64
  @sudo mkdir -p ./mnt/testcases
  @sudo cp /lib/x86_64-linux-gnu/libc.so.6 ./mnt/lib/
  @sudo cp /lib64/ld-linux-x86-64.so.2 ./mnt/lib64/
  @sudo cp -r ./btp/build/x86_64/sbin ./mnt/
  -@sudo cp -f $(LTP)/build_x86_64/testcases/bin/mmap[[:digit:]]* ./mnt/testcases/
  ls -l ./mnt/lib
  ls -l ./mnt/lib64
  ls -l ./mnt/sbin
  ls -l ./mnt/testcases
  @sudo umount ./mnt
  @rm -rf mnt
endef
