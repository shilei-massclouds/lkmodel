TARGETS := init hello vfork execl runltp signal mmap procfs mount \
	mkdir runbtp devfs cmd_system pthread named_pipe pipe cred

CC := $(AX_ARCH)-linux-gnu-gcc
STRIP := $(AX_ARCH)-linux-gnu-strip
DST_DIR := ./build/$(AX_ARCH)/sbin
PREFIX_TARGETS := $(addprefix $(DST_DIR)/,$(TARGETS))

all: $(PREFIX_TARGETS)

$(DST_DIR)/%: %.c
	@mkdir -p $(DST_DIR)
	$(CC) $< -o $@
	$(STRIP) $@

clean:
	@rm -rf ./build
