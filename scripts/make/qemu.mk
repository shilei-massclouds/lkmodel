# QEMU arguments

QEMU := qemu-system-$(ARCH)

ifeq ($(BUS), mmio)
  vdev-suffix := device
else ifeq ($(BUS), pci)
  vdev-suffix := pci
else
  $(error "BUS" must be one of "mmio" or "pci")
endif

qemu_args-x86_64 := \
  -machine q35 \
  -kernel $(OUT_ELF)

qemu_args-riscv64 := \
  -machine virt \
  -bios default \
  -kernel $(OUT_BIN)

qemu_args-aarch64 := \
  -cpu cortex-a72 \
  -machine virt \
  -kernel $(OUT_BIN)

qemu_args-loongarch64 := \
  -kernel $(OUT_ELF)

ifeq ($(ARCH), loongarch64)
qemu_args-y := -smp $(SMP) $(qemu_args-$(ARCH))
else
qemu_args-y := -m 256M -smp $(SMP) $(qemu_args-$(ARCH))
endif

ifneq ($(INIT), )
  qemu_args-y += -append "init=$(INIT)"
endif

qemu_args-$(BLK) += \
  -device virtio-blk-$(vdev-suffix),drive=disk0 \
  -drive id=disk0,if=none,format=raw,file=$(DISK_IMG)

qemu_args-$(NET) += \
  -device virtio-net-$(vdev-suffix),netdev=net0

ifeq ($(NET_DEV), user)
  qemu_args-$(NET) += -netdev user,id=net0,hostfwd=tcp::5555-:5555,hostfwd=udp::5555-:5555
else ifeq ($(NET_DEV), tap)
  qemu_args-$(NET) += -netdev tap,id=net0,ifname=tap0,script=no,downscript=no
else
  $(error "NET_DEV" must be one of "user" or "tap")
endif

ifeq ($(NET_DUMP), y)
  qemu_args-$(NET) += -object filter-dump,id=dump0,netdev=net0,file=netdump.pcap
endif

qemu_args-$(GRAPHIC) += \
  -device virtio-gpu-$(vdev-suffix) -vga none \
  -serial mon:stdio

ifeq ($(GRAPHIC), n)
  qemu_args-y += -nographic
endif

ifeq ($(QEMU_LOG), y)
  qemu_args-y += -D qemu.log -d in_asm,int,mmu,pcall,cpu_reset,guest_errors
endif

qemu_args-debug := $(qemu_args-y) -s -S

# Do not use KVM for debugging
ifeq ($(shell uname), Darwin)
  qemu_args-$(ACCEL) += -cpu host -accel hvf
else
  qemu_args-$(ACCEL) += -cpu host -accel kvm
endif

qemu_args-$(DUMP_OUTPUT) += 1>/tmp/output.log

ifeq ($(PLATFORM_NAME), um)
  define run_qemu
    @printf "    $(CYAN_C)Running$(END_C) on host...\n"
    $(call run_cmd,$(OUT_ELF))
  endef

  define run_qemu_debug
    @printf "    $(CYAN_C)Debugging$(END_C) on host...\n"
    $(call run_cmd,$(OUT_ELF))
  endef
else
  define run_qemu
    @printf "    $(CYAN_C)Running$(END_C) on qemu...\n"
    $(call run_cmd,$(QEMU),$(qemu_args-y))
  endef

  define run_qemu_debug
    @printf "    $(CYAN_C)Debugging$(END_C) on qemu...\n"
    $(call run_cmd,$(QEMU),$(qemu_args-debug))
  endef
endif
