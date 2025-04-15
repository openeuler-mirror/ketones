# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Author: Jackie Liu <liuyun01@kylinos.cn>
# Copyright @ KYLIN - 2024
#

ifeq ($(V),1)
	Q =
	MSG =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'                                   \
			"$(1)"                                          \
			"$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"     \
			"$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory --quiet
endif

ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/' \
	| sed 's/ppc64le/powerpc/' | sed 's/mips.*/mips/' \
	| sed 's/riscv64/riscv/' | sed 's/loongarch.*/loongarch/' \
	| sed 's/s390x/s390/')

CLANG ?= clang
LLVM_STRIP ?= llvm-strip
INSTALL := install
CC = gcc
CP := cp
LN := ln
RM := rm
