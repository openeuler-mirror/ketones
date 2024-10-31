Name: ketones
Version: 1.0
Release: 1%{?dist}
Summary: The key eBPF tool for a new environment
License: GPLv3 License
URL: https://gitee.com/openkylin/ketones.git
Source0: %{name}-%{version}.tar.gz
BuildRequires: make, binutils-devel, libcap-devel, llvm-devel, numactl-devel, elfutils-libelf-devel
BuildRequires: zlib-devel, gcc, clang >= 10
Suggests: numactl-libs

%description
Our software is a powerful eBPF program assembly designed to help
users run programs in various environments. It aims to replace the BCC toolset
and provides additional tools for observing the kernel. With a small footprint,
easy integration, and compatibility with different kernels, our software is
versatile and efficient. It supports running in container environments without
the need for installing a compilation environment.

%prep
%autosetup

%build
export LDFLAGS=
%make_build

%install
%make_install

%files
%{_bindir}/*
%license LICENSE

%changelog
* Wed Oct 18 2023 Jackie Liu <liuyun01@kylinos.cn> - 1.0-1
- inject: add missing -h args
- filesnoop: fix crash when -o OPEN
- Add dbstat support
- Add ustat support
- Add inject support
- tcplinks: fix typo for helps
- Add icstat support
- memleak: Tiny fixes
- memleak: Fix memory leak
- Fix memory leak when using getline()
- dbslower: Fixes build errors caused by uninitialized variables in bpf program
- Add dbslower support
- Add ugc support
- Add mysqld-qslower support
- javagc: fix some attach errors
- Add uflow support
- ucalls: Correct 'phpccalls' to 'phpcalls'
- Add cachetop support
- biotop/filetop: Fix 'count' print count
- Add get_uid_name() implementation
- Add trace support
- Display UID in username format
- libbpf-tools: update arm vmlinux with missing perf_event, BPF_PROG_TYPE_PERF_EVENT
- setuids: rename UID to SU_UID
- filegone: convert errno to error string
- filegone: Increase the buffer for filename
- filegone: Add return code support
- Expand the print width of pid
- libbpf-tools/filelife: Check btf struct field for CO-RE
- tplist: Use tracefs_path()
- Add reset-trace support
- Tiny fixes
- libbpf-tools/tcprtt: use the same options to filter IPv4 and IPv6 addresses
- tools, libpf-tools: increase IPv6 address width to 39 characters
- Fix memory leak in capable.c
- libbpf-tools/execsnoop: fix ret type of bpf_probe_read_user*.
- libbpf-tools: add block_io_{start,done} tracepoints support to bio tools
- libbpf-tools: fix tcppktlat show wrong ports
- Tiny fix we meet
- funcslower/profile/stackcount: Add folded format output
- filegone: rewrite filegone base on unlinksnoop
- offwaketime/wakeuptime: Add folded format output
- offcputime: Add folded format output
- Add offwaketime support
- offcputime: Change the tracepoint mode to kprobe to repair the calltrace display
- ketones: reword new software tagline
- dcstat: fix macro err defined
- Add uthreads support
- Fix potential double fclose warning
- Use bpf_core_filed_exist for bpf_ringbuf exist
- Fix allocating and freeing memory in {probe,free}_usdt_notes
- Add shmsnoop support
- uobjnew: Adjust this program to better match the BCC version
- Add uobjnew support
- Add tplist support
- package: Prompt for compilation dependencies
- Add unlinksnoop support
- Add dcstat support
- core_fixes: Fix __builtin_preserve_enum_value not defined issue
- libbpf-tools: Allow tcppktlat to run on old kernels
- libbpf-tools: Add support for IPv6 to tcprtt.
- libbpf-tools: fallback to tracefs mount point if debugfs is not mounted
- libbpf-tools: add filter for biosnoop
- cpufreq: read initial freqs only of valid links
- libbpf-tools: Avoid virtual memory area [uprobes] warning
- statsnoop: print parent pid
- opensnoop: print parent pid
- filesnoop: drop opensnoop and statsnoop in filesnoop
- Revert "statsnoop: Remove specially designed statsnoop"
- filesnoop: extend parent pid
- debian rules to package ketones
- prepare for make project
- statsnoop: Remove specially designed statsnoop
- libbpf: Support POSIX regular expressions for multi kprobe
- Add tcprst support
- Add ucalls support
- uprobe_helpers: Fix path acquisition function
- libbpf-tools: syscount: Add syscall lookup table for arm64 and riscv
- Add profile support
- Add tcpdrop support
- tcplinks: use ncurses for draw UI
- libbpf: tiny fixup of libbpf
- Add tcpsubnet support
- Add tcplinks support
- libbpf: don't attach to non-attachable kprobes
- Add stackcount support
- libbpf: don't need zero res in exit path
- libbpf: available_filter_functions_addrs for filter functions
- Fix the function to get the sk_protocol
- tcpaccept: Delete redundant code to make more compact
- tcp: Delete unnecessary parameters
- Add zfsslower support
- Add zfsdist support
- Add funcslower support
- signal: fix undefined behavior of signal handler
- commons: Simplified time_since_start function
- Add tcpaccept support
- Makefile: fix compile error for bpflist
- Add tcpretrans support
- ttysnoop: Implement new way for CO-RE
- libbpf: rewrite kprobe.multi filter with available_filter_functions
- Add funccount support
- Resolve compilation errors on loongarch
- libbpf: support record count of functions has been traced
- Makefile: bpflist: remove unnecessary compilation dependencies
- libbpf: filter by available functions
- Add vfscount support and cleanup unused variable
- Add README
- Add filesnoop support
- Add bpflist support
- Add stacksnoop support
- Add writeback support
- vfsstat: fix exit value when SIGINT
- Add threadsnoop support
- trace_helpers: fix proc maps with [uprobes] entry
- Add syncsnoop support
- Cleanup vmlinux and others
- loads: register perf event on all cpus
- klockstat: fix running on un-implement down_read_interruptible kernel
- loads: Remove unnecessary assign 0 operations
- readahead: fix CO-RE on running without fentry
- memleak: fix kmalloc and kmalloc_node's hook running on old kernel
- Makefile: fix foo.bpf.o build without foo.h
- libbpf-tools: Add loongarch support
- libbpf-tools: use fentry in funclatency
- libbpf-tools: Filter with kprobe blacklist for kprobe_exists() api.
- libbpf-tools/memleak: support ksyms and syms_cache
- libbpf-tools/memleak: make it run on old kernel
- change storage type of helper err to int
- libbpf-tools/memleak: remove unused arg "PERCPU"
- libbpf-tools/memleak: fix 'show allocs'
- Makefile: fix binary depends on includes file update
- ttysnoop: fix co-re on struct iov_iter hasn't ubuf
- loads: sample_period works on ns, convert to second
- Add setuids support
- Sync upstream bpftool libbpf blazesym without submodules
- Redefine the global name of the project and its representative meanings
- Add ttysnoop support
- Move various tracing programs to his directory
- Move binary to ./bin directory
- Spit includes and libs into directory
- Add pidpersec support
- Add naptime support
- Add cpuwalk support
- Add dcsnoop support
- Add loads support
- Add swapin support
- Add tcppktlat support
- Add javagc support
- Add tcpstates support
- Add tcprtt support
- Add tcplife support
- tcpconnect: Drop unused ts_us
- Add tcpconnect support
- Fix some string features must be done in _GNU_SOURCE
- Fix potential early exit of the program
- Add tcpsynbl support
- Add tcptop support
- Add tcptracer support
- Use strftime_now for cleanup
- Add vfsstat support
- Use BPF_CORE_READ_STR_INTO to instead of bpf_probe_read_kernel_str
- Add syscount support
- Merge changes If1eb510b,I220234bb
- tcpconnlat: Remove entries from map in all cases
- execsnoop: add execveat support
- Fix load of ringbuffer is not support
- Add tcpconnlat support
- Add statsnoop support
- Add solisten support
- Add support slabratetop
- Add sigsnoop support
- Add support readahead
- Add opensnoop support
- update submodules url into gitee.com
- Add support oomkill
- Add support mountsnoop
- Use argp_parse_pid and do_process_running wrapper for cleanup
- memleak: use blazesym for show symbols
- Add support blazesym
- Makefile: Generate a symlink for different ebpf programs
- Add support memleak
- Add support mdflush
- Update submodules
- Add support llcstat
- Add support ksnoop
- rename bpf_map_lookup_and_delete to bpf_map_lookup_and_delete_elem
- Add support klockstat
- biostacks: fix wrong function name of __blk_account_io_start
- biosnoop.bpf: fix run by inline functions
- cpufreq: fix typo from raw_btf to raw_tp
- biostacks: support run on kernel without btf
- offcputime: work on kernel without btf
- fsdist: fix crash on kernel without bss support
- cpufreq: work on kernel without btf
- bitesize: fix run on kernel without btf
- biosnoop: support kernel without fentry
- numamove: fix initial of num and latency
- Add fsslower support
- Drop libbpf_set_strict_mode() calls
- Add support fsdist
- bitesize: add missing partitions__load
- Add support filetop
- Use bpf_get_current_ns_pid_tgid for WSL or container
- Add support filelife
- Add support exitsnoop
- Add drsnoop support
- Add support capable
- Add support cachestat
- Add support bitesize
- Add support biostacks
- Add support biosnoop
- Add support biopattern
- Add support biolatency
- Add support bindsnoop
- Add support cpufreq
- Add biotop support
- Add support funclatency
- Add gethostlatency support
- Add bash readline support
- numamove: only work for numa node > 1
- runqlen: Add run queue length support
- execsnoop: convert to use bpf_core_read_xxx
- Add numasched support
- execsnoop: works on !(tracepoint/syscalls)
- numamove: fixes BPF_KRETPROBE for kretprobe
- update vmlinux.h
- Add numamove support
- Fix wrong patch of uapi/linux/bpf.h
- Add wakeuptime support
- Add execsnoop support
- Add support offcputime
- Add support cpudist
- Add support runqueue-latency
- Add support hardirqs
- use warning instead of fprintf stderr
- Add softirqs support
- runqslower support thread id
- Add .gitreview for git-review
- Add README.md for build binary
- Add runqslower tools
- Init submodules
- Initial LICENSE
