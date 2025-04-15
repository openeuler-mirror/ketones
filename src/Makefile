# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Author: Jackie Liu <liuyun01@kylinos.cn>
# Copyright @ 2024 KYLIN Software

include Makefile.inc

APPS += adaptive-readahead
APPS += bashreadline
APPS += bindsnoop
APPS += biolatency
APPS += biolatpcts
APPS += biopattern
APPS += biosnoop
APPS += biostacks
APPS += biotop
APPS += bitesize
APPS += cachestat
APPS += cachetop
APPS += capable
APPS += compactsnoop
APPS += cpudist
APPS += cpufreq
APPS += cpuunclaimed
APPS += cpuwalk
APPS += criticalstat
APPS += dbslower
APPS += dbstat
APPS += dcsnoop
APPS += dcstat
APPS += dddos
APPS += dirtop
APPS += drsnoop
APPS += execsnoop
APPS += exitsnoop
APPS += filegone
APPS += filelife
APPS += filetop
APPS += filesnoop
APPS += fsdist
APPS += fsslower
APPS += funccount
APPS += funcinterval
APPS += funclatency
APPS += funcslower
APPS += futexctn
APPS += gethostlatency
APPS += hardirqs
APPS += icstat
APPS += inject
APPS += javagc
APPS += klockstat
APPS += ksnoop
APPS += kvmexit
APPS += llcstat
APPS += loads
APPS += mdflush
APPS += memleak
APPS += mountsnoop
APPS += mysqld-qslower
APPS += naptime
APPS += netfilter
APPS += netqtop
APPS += numamove
APPS += numasched
APPS += offcputime
APPS += offwaketime
APPS += oomkill
APPS += opensnoop
APPS += pidpersec
APPS += profile
APPS += readahead
APPS += runqlen
APPS += runqslower
APPS += runqueue-latency
APPS += setuids
APPS += shmsnoop
APPS += sigsnoop
APPS += slabratetop
APPS += sofdsnoop
APPS += softirqs
APPS += solisten
APPS += sslsniff
APPS += stackcount
APPS += stacksnoop
APPS += statsnoop
APPS += syncsnoop
APPS += syscount
APPS += swapin
APPS += tcpaccept
APPS += tcpcong
APPS += tcpconnect
APPS += tcpconnlat
APPS += tcpdrop
APPS += tcplife
APPS += tcplinks
APPS += tcppktlat
APPS += tcpretrans
APPS += tcprst
APPS += tcprtt
APPS += tcpstates
APPS += tcpsubnet
APPS += tcpsynbl
APPS += tcptop
APPS += tcptracer
APPS += threadsnoop
APPS += trace
APPS += ttysnoop
APPS += ucalls
APPS += ugc
APPS += uflow
APPS += uthreads
APPS += uobjnew
APPS += ustat
APPS += vfsstat
APPS += virtiostat
APPS += wakeuptime
APPS += wqlat
APPS += writeback

.PHONY: all clean $(APPS)

default: all

TOPDIR := ..
OUTPUT := .output
OUTPUT_ABS := $(abspath $(OUTPUT))

BPFTOOL_SRC := $(abspath ../bpftool/src)
BPFTOOL_OUTPUT ?= $(OUTPUT)/bpftool
BPFTOOL_OUTPUT_ABS ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bpftool

LIBBPF_SRC := $(abspath ../libbpf/src)
LIBBPF_OBJ ?= $(OUTPUT)/libbpf.a

BINARIES_DIR := ./bin
CFLAGS := -g -O0 -Wall $(CLANG_CROSS_FLAGS) -Wunused-variable -Wmissing-field-initializers -Werror -Werror=undef

VMLINUX := $(TOPDIR)/vmlinux/$(ARCH)/vmlinux.h
INCLUDES := -I$(OUTPUT) -I$(OUTPUT)/include -I$(dir $(VMLINUX)) \
            -Iinclude -I.

$(OUTPUT)/libbpf:
	$(call msg,MKDIR,$(notdir $@))
	$(Q)mkdir -p $@

$(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$(notdir $@))
	$(Q)mkdir -p $@

$(OUTPUT)/libs:
	$(call msg,MKDIR,$(notdir $@))
	$(Q)mkdir -p $@

$(BINARIES_DIR):
	$(call msg,MKDIR,$(notdir $@))
	$(Q)mkdir -p $@

.PHONY: libbpf-headers
libbpf-headers: | $(OUTPUT)/include

# Build libbpf.a
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$(notdir $@))
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1                	\
		OBJDIR=$(OUTPUT_ABS)/libbpf PREFIX=$(OUTPUT_ABS) DESTDIR=	\
		LIBDIR=$(OUTPUT_ABS)/						\
		install install_uapi_headers

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$(notdir $@))
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT_ABS)/ -C $(BPFTOOL_SRC)

# Build common libs objects
$(OUTPUT_ABS)/libs/%.o: libs/%.c $(LIBBPF_OBJ) | $(OUTPUT)/libs
	$(call msg,CC,$(notdir $@))
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

COMMON_LIBS_OBJ := $(patsubst %.c,$(OUTPUT_ABS)/%.o,$(wildcard libs/*.c))

all: $(APPS)

$(APPS): $(BPFTOOL) $(LIBBPF_OBJ) $(COMMON_LIBS_OBJ) | $(BINARIES_DIR)
	$(MAKE) -C $@ COMMON_LIBS_OBJ="$(COMMON_LIBS_OBJ)" CFLAGS="$(CFLAGS)"

install:
	$(INSTALL) -d ${bindir}/
	$(CP) -P bin/* ${bindir}/

clean:
	for dir in $(APPS); do \
		$(MAKE) -C $$dir clean; \
	done
	$(call msg,CLEAN,OUTPUT)
	$(Q)rm -rf $(OUTPUT)
	$(call msg,CLEAN,BIN)
	$(Q)rm -rf $(BINARIES_DIR)
