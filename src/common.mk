# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Author: Jackie Liu <liuyun01@kylinos.cn>
# Copyright @ KYLIN - 2024
#

include ../Makefile.inc

TOPDIR := ../..
TOPSRCDIR := ..
OUTPUT ?= $(TOPSRCDIR)/.output

LIBBPF_SRC := $(TOPDIR)/libbpf/src
BPFTOOL_SRC := $(TOPDIR)/bpftool/src
LIBBPF_OBJ := $(OUTPUT)/libbpf.a
BPFTOOL_OUTPUT ?= $(OUTPUT)/bpftool
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bpftool
BINARIES_DIR := $(TOPSRCDIR)/bin

VMLINUX := $(TOPDIR)/vmlinux/$(ARCH)/vmlinux.h
INCLUDES := -I$(OUTPUT) -I$(OUTPUT)/include -I$(dir $(VMLINUX)) \
	    -I$(TOPSRCDIR)/include -I.

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
	  $(findstring command line,$(origin $(1)))),,\
	  $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

define alias-override
$(1): $(addprefix $(BINARIES_DIR)/, $(2))
	$(call msg,SYMLINK,$$(@F))
	$(Q)$(LN) -f -s $(2) $$@

_CLEANUP:
	rm -rf $(1)

all: $(1)
clean: _CLEANUP
endef

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
        | sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

# Target
TARGET		:= $(shell basename $(shell dirname $(realpath Makefile)))
.DEFAULT_GOAL	:= all  # Set default goal to all

all: $(BINARIES_DIR)/$(TARGET)

# Get all .c and .bpf.c files
SRC		:= $(wildcard *.c)
BPF_SRC		:= $(filter %.bpf.c,$(SRC))
NORMAL_SRC	:= $(filter-out %.bpf.c,$(SRC))

# Generate object and other file paths
OBJ		:= $(patsubst %.c,$(OUTPUT)/%.o,$(NORMAL_SRC))
BPF_OBJ		:= $(patsubst %.bpf.c,$(OUTPUT)/%.bpf.o,$(BPF_SRC))
BPF_SKEL	:= $(patsubst %.bpf.c,$(OUTPUT)/%.skel.h,$(BPF_SRC))

# Build BPF Code
$(OUTPUT)/%.bpf.o: %.bpf.c $(wildcard $(TOPDIR)/src/include/*.bpf.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$(notdir $@))
	$(Q)$(CLANG) -Wunused-variable -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $< -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$(notdir $@))
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(BPF_SKEL): $(BPF_OBJ)

# Normal object, depends on the corresponding skel.h
$(OUTPUT)/%.o: %.c $(BPF_SKEL)
	$(call msg,CC,$(notdir $@))
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@ -DSKEL_NAME=$(shell basename $(shell dirname $(realpath $<)))_bpf

$(BINARIES_DIR)/$(TARGET): $(OBJ) $(LIBBPF_OBJ) | $(OUTPUT) $(BINARIES_DIR)
	$(call msg,BINARY,$(notdir $@))
	$(Q)$(CC) $(CFLAGS) $(COMMON_LIBS_OBJ) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

.PHONY: clean
clean:
	$(call msg,CLEAN,$(TARGET))
	$(Q)$(RM) -rf $(OBJ) $(BPF_OBJ) $(BPF_SKEL) $(BINARIES_DIR)/$(TARGET)

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
