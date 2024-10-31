// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
// Copyright @ 2023 - Kylin
// Author: Yun Lu <luyun@kylinos.cn>
//
// Based on ustat.py - Sasha Goldshtein

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>
#include "maps.bpf.h"
#include "compat.bpf.h"
#include "ustat.h"

#define DEF_MAP_COUNTS(map_name)		\
struct {					\
	__uint(type, BPF_MAP_TYPE_HASH);	\
	__uint(max_entries, MAX_ENTRIES);	\
	__type(key, __u32);			\
	__type(value, __u64);			\
} map_name SEC(".maps")

DEF_MAP_COUNTS(java_gc_counts);
DEF_MAP_COUNTS(java_thread_counts);
DEF_MAP_COUNTS(java_cload_counts);
DEF_MAP_COUNTS(java_objnew_counts);
DEF_MAP_COUNTS(java_method_counts);
DEF_MAP_COUNTS(java_excp_counts);
DEF_MAP_COUNTS(node_gc_counts);
DEF_MAP_COUNTS(perl_method_counts);
DEF_MAP_COUNTS(php_method_counts);
DEF_MAP_COUNTS(php_cload_counts);
DEF_MAP_COUNTS(php_excp_counts);
DEF_MAP_COUNTS(python_method_counts);
DEF_MAP_COUNTS(python_gc_counts);
DEF_MAP_COUNTS(ruby_method_counts);
DEF_MAP_COUNTS(ruby_gc_counts);
DEF_MAP_COUNTS(ruby_objnew_counts);
DEF_MAP_COUNTS(ruby_cload_counts);
DEF_MAP_COUNTS(ruby_excp_counts);
DEF_MAP_COUNTS(tcl_method_counts);
DEF_MAP_COUNTS(tcl_objnew_counts);

#define DEF_BPF_FUNC(func_name, map_name)				\
SEC("usdt")								\
int BPF_USDT(func_name)							\
{									\
	__u64 zero = 0, *valp;						\
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;			\
	valp = bpf_map_lookup_or_try_init(&map_name, &tgid, &zero);	\
	if (valp)							\
		(*valp)++;						\
	return 0;							\
}

DEF_BPF_FUNC(trace_java_gc__begin, java_gc_counts)
DEF_BPF_FUNC(trace_java_mem__pool__gc__begin, java_gc_counts)
DEF_BPF_FUNC(trace_java_thread__start, java_thread_counts)
DEF_BPF_FUNC(trace_java_class__loaded, java_cload_counts)
DEF_BPF_FUNC(trace_java_object__alloc, java_objnew_counts)
DEF_BPF_FUNC(trace_java_method__entry, java_method_counts)
DEF_BPF_FUNC(trace_java_ExceptionOccurred__entry, java_excp_counts)
DEF_BPF_FUNC(trace_node_gc_start, node_gc_counts)
DEF_BPF_FUNC(trace_perl_sub__entry, perl_method_counts)
DEF_BPF_FUNC(trace_php_function__entry, php_method_counts)
DEF_BPF_FUNC(trace_php_compile__file__entry, php_cload_counts)
DEF_BPF_FUNC(trace_php_exception__thrown, php_excp_counts)
DEF_BPF_FUNC(trace_python_function__entry, python_method_counts)
DEF_BPF_FUNC(trace_python_gc__start, python_gc_counts)
DEF_BPF_FUNC(trace_ruby_method__entry, ruby_method_counts)
DEF_BPF_FUNC(trace_ruby_cmethod__entry, ruby_method_counts)
DEF_BPF_FUNC(trace_ruby_gc__mark__begin, ruby_gc_counts)
DEF_BPF_FUNC(trace_ruby_gc__sweep__begin, ruby_gc_counts)
DEF_BPF_FUNC(trace_ruby_object__create, ruby_objnew_counts)
DEF_BPF_FUNC(trace_ruby_hash__create, ruby_objnew_counts)
DEF_BPF_FUNC(trace_ruby_string__create, ruby_objnew_counts)
DEF_BPF_FUNC(trace_ruby_array__create, ruby_objnew_counts)
DEF_BPF_FUNC(trace_ruby_require__entry, ruby_cload_counts)
DEF_BPF_FUNC(trace_ruby_load__entry, ruby_cload_counts)
DEF_BPF_FUNC(trace_ruby_raise, ruby_excp_counts)
DEF_BPF_FUNC(trace_tcl_proc__entry, tcl_method_counts)
DEF_BPF_FUNC(trace_tcl_obj__create, tcl_objnew_counts)

char LICENSE[] SEC("license") = "GPL";
