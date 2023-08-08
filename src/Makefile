# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
OUTPUT ?= $(abspath .output)
CLANG ?= clang
LLVM_STRIP ?= llvm-strip

LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bpftool
LIBBLAZESYM_SRC := $(abspath ../blazesym/target/release/libblazesym.a)
BINARIES_DIR := $(abspath ./bin)

INSTALL := install
CP := cp
LN := ln

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' | sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/' | sed 's/loongarch64/loongarch/')
VMLINUX := ../vmlinux/$(ARCH)/vmlinux.h

ifeq ($(ARCH),x86)
CARGO ?= $(shell which cargo)
ifeq ($(strip $(CARGO)),)
USE_BLAZESYM ?= 0
else
USE_BLAZESYM ?= 1
endif
endif

INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi -I$(dir $(VMLINUX)) -I./include
CFLAGS := -g -Wall $(CLANG_CROSS_FLAGS) -Wunused-variable
ifeq ($(USE_BLAZESYM),1)
CFLAGS  += -DUSE_BLAZESYM=1
LDFLAGS += $(OUTPUT)/libblazesym.a -lrt -lpthread -ldl
endif
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

BZ_APPS += memleak
BZ_APPS += opensnoop

APPS += bashreadline
APPS += bindsnoop
APPS += biolatency
APPS += biopattern
APPS += biosnoop
APPS += biostacks
APPS += biotop
APPS += bitesize
APPS += cachestat
APPS += capable
APPS += cpudist
APPS += cpufreq
APPS += cpuwalk
APPS += dcsnoop
APPS += dcstat
APPS += drsnoop
APPS += execsnoop
APPS += exitsnoop
APPS += filelife
APPS += filetop
APPS += filesnoop
APPS += fsdist
APPS += fsslower
APPS += funccount
APPS += funclatency
APPS += funcslower
APPS += gethostlatency
APPS += hardirqs
APPS += javagc
APPS += klockstat
APPS += ksnoop
APPS += llcstat
APPS += loads
APPS += mdflush
APPS += mountsnoop
APPS += naptime
APPS += numamove
APPS += numasched
APPS += offcputime
APPS += offwaketime
APPS += oomkill
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
APPS += softirqs
APPS += solisten
APPS += stackcount
APPS += stacksnoop
APPS += statsnoop
APPS += syncsnoop
APPS += syscount
APPS += swapin
APPS += tcpaccept
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
APPS += ttysnoop
APPS += ucalls
APPS += uthreads
APPS += unlinksnoop
APPS += uobjnew
APPS += vfsstat
APPS += wakeuptime
APPS += writeback
APPS += $(BZ_APPS)

COMMON_LIBS_OBJ := $(OUTPUT)/libs/trace_helpers.o
COMMON_LIBS_OBJ += $(OUTPUT)/libs/uprobe_helpers.o
COMMON_LIBS_OBJ += $(OUTPUT)/libs/btf_helpers.o
COMMON_LIBS_OBJ += $(OUTPUT)/libs/map_helpers.o
COMMON_LIBS_OBJ += $(OUTPUT)/libs/compat.o
COMMON_LIBS_OBJ += $(OUTPUT)/libs/syscall_helpers.o
COMMON_LIBS_OBJ += $(OUTPUT)/libs/errno_helpers.o

ifeq ($(USE_BLAZESYM),1)
COMMON_LIBS_OBJ += $(OUTPUT)/libblazesym.a
COMMON_LIBS_OBJ += $(OUTPUT)/blazesym.h
endif

FSDIST_ALIASES	 := $(addprefix $(BINARIES_DIR)/, btrfsdist ext4dist nfsdist xfsdist zfsdist)
FSSLOWER_ALIASES := $(addprefix $(BINARIES_DIR)/, btrfsslower ext4slower nfsslower xfsslower zfsslower)
SIGSNOOP_ALIAS := $(addprefix $(BINARIES_DIR)/, killsnoop)
FILESNOOP_ALIAS := $(addprefix $(BINARIES_DIR)/, closesnoop writesnoop readsnoop)
FUNCCOUNT_ALIAS := $(addprefix $(BINARIES_DIR)/, vfscount)
UCALLS_ALIAS := $(addprefix $(BINARIES_DIR)/, javacalls perlcalls phpccalls \
		pythoncalls rubycalls tclcalls)
UOBJNEW_ALIAS := $(addprefix $(BINARIES_DIR)/, cobjnew javaobjnew rubyobjnew tclobjnew)
UTHREADS_ALIAS := $(addprefix $(BINARIES_DIR)/, javathreads)

ifeq ($(NOALIASES),)
APP_ALIASES := $(FSDIST_ALIASES) $(FSSLOWER_ALIASES) $(SIGSNOOP_ALIAS) $(FILESNOOP_ALIAS) \
	       $(FUNCCOUNT_ALIAS) $(UCALLS_ALIAS) $(UOBJNEW_ALIAS) $(UTHREADS_ALIAS)
endif

OUTPUT_BINARIES := $(addprefix $(BINARIES_DIR)/, $(APPS))

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

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
			"$(1)"						\
			"$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
			"$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
	    $(findstring command line,$(origin $(1)))),,\
	$(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(OUTPUT_BINARIES) $(APP_ALIASES) bin/bpflist bin/tplist

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(BINARIES_DIR) $(APP_ALIASES)

$(LIBBLAZESYM_SRC)::
	$(Q)cd ../blazesym && cargo build --release

$(OUTPUT)/libblazesym.a: $(LIBBLAZESYM_SRC) | $(OUTPUT)
	$(call msg,LIB,$@)
	$(Q)cp $(LIBBLAZESYM_SRC) $@

$(OUTPUT)/blazesym.h: $(LIBBLAZESYM_SRC) | $(OUTPUT)
	$(call msg,INC,$@)
	$(Q)cp ../blazesym/include/blazesym.h $@

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT) $(OUTPUT)/libs $(BINARIES_DIR):
	$(call msg,MKDIR,$(notdir $@))
	$(Q)mkdir -p $@

# Build libbpf.a
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$(notdir $@))
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		\
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		\
		    INCLUDEDIR= LIBDIR= UAPIDIR=			\
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$(notdir $@))
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC)

# Build BPF Code
$(OUTPUT)/%.bpf.o: %/*.bpf.c $(LIBBPF_OBJ) $(wildcard include/*.bpf.h) $(VMLINUX) | $(OUTPUT)
	$(call msg,BPF,$(notdir $@))
	$(Q)$(CLANG) -Wunused-variable -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) -c $< -o $@
	$(Q)$(LLVM_STRIP) -g $@ # strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$(notdir $@))
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
$(patsubst %,$(OUTPUT)/%.o,$(APPS)): %.o: %.skel.h

$(OUTPUT)/libs/%.o: libs/%.c include/%.h $(LIBBPF_OBJ) | $(OUTPUT)/libs
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

$(OUTPUT)/%.o: %/*.c $(wildcard include/*.h) $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(lastword $(filter %.c, $(sort $^))) -o $@

# Build application binary
$(BINARIES_DIR)/%: $(OUTPUT)/%.o $(COMMON_LIBS_OBJ) $(LIBBPF_OBJ) | $(OUTPUT) $(BINARIES_DIR)
	$(call msg,BINARY,$(notdir $@))
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

$(addprefix $(BINARIES_DIR)/, numasched numamove): ALL_LDFLAGS += -lnuma
$(addprefix $(BINARIES_DIR)/, tcplinks): ALL_LDFLAGS += -lncurses

# Build user application binary
bin/bpflist: bpflist/bpflist.c include/commons.h $(LIBBPF_OBJ) | $(BINARIES_DIR)
	$(call msg,BINARY,$(notdir $@))
	$(Q)$(CC) $(CFLAGS) $< $(INCLUDES) -lelf -lz -o $@

bin/tplist: tplist/tplist.c $(COMMON_LIBS_OBJ) $(LIBBPF_OBJ) | $(BINARIES_DIR)
	$(call msg,BINARY,$(notdir $@))
	$(Q)$(CC) $(CFLAGS) $^ $(INCLUDES) -lelf -lz -o $@

ifeq ($(USE_BLAZESYM),1)
$(patsubst %,$(OUTPUT)/%.o,$(BZ_APPS)): $(OUTPUT)/blazesym.h
endif

$(FSSLOWER_ALIASES): $(addprefix $(BINARIES_DIR)/, fsslower)
	$(call msg,SYMLINK,$(notdir $@))
	$(Q)$(LN) -f -s $(notdir $^) $@

$(FSDIST_ALIASES): $(addprefix $(BINARIES_DIR)/, fsdist)
	$(call msg,SYMLINK,$(notdir $@))
	$(Q)$(LN) -f -s $(notdir $^) $@

$(SIGSNOOP_ALIAS): $(addprefix $(BINARIES_DIR)/, sigsnoop)
	$(call msg,SYMLINK,$(notdir $@))
	$(Q)$(LN) -f -s $(notdir $^) $@

$(FILESNOOP_ALIAS): $(addprefix $(BINARIES_DIR)/, filesnoop)
	$(call msg,SYMLINK,$(notdir $@))
	$(Q)$(LN) -f -s $(notdir $^) $@

$(FUNCCOUNT_ALIAS): $(addprefix $(BINARIES_DIR)/, funccount)
	$(call msg,SYMLINK,$(notdir $@))
	$(Q)$(LN) -f -s $(notdir $^) $@

$(UCALLS_ALIAS): $(addprefix $(BINARIES_DIR)/, ucalls)
	$(call msg,SYMLINK,$(notdir $@))
	$(Q)$(LN) -f -s $(notdir $^) $@

$(UOBJNEW_ALIAS): $(addprefix $(BINARIES_DIR)/, uobjnew)
	$(call msg,SYMLINK,$(notdir $@))
	$(Q)$(LN) -f -s $(notdir $^) $@

$(UTHREADS_ALIAS): $(addprefix $(BINARIES_DIR)/, uthreads)
	$(call msg,SYMLINK,$(notdir $@))
	$(Q)$(LN) -f -s $(notdir $^) $@

install:
	$(INSTALL) -d ${bindir}/
	$(CP) -P bin/* ${bindir}/

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
