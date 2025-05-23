#ifndef __COMMONS_H
#define __COMMONS_H

#ifndef _GNU_SOURCE
  #define _GNU_SOURCE
#endif

#include <argp.h>
#include <pwd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#define warning(...) fprintf(stderr, __VA_ARGS__)

#ifndef NSEC_PER_SEC
#define NSEC_PER_SEC		1000000000ULL
#endif
#define ARRAY_SIZE(x)		(sizeof(x) / sizeof(*(x)))
#define PERF_BUFFER_PAGES	64
#define PERF_POLL_TIMEOUT_MS	100

#define max(x, y) ({				\
		typeof(x) __max1 = (x);			\
		typeof(y) __max2 = (y);			\
		(void) (&__max1 == &__max2);		\
		__max1 > __max2 ? __max1 : __max2; })

#define min(x, y) ({				\
		typeof(x) __min1 = (x);			\
		typeof(y) __min2 = (y);			\
		(void) (&__min1 == &__min2);		\
		__min1 > __min2 ? __min2 : __min1; })

#define folded_printf(folded, format, ...)	\
({						\
	if (!folded)				\
		printf("    ");			\
	printf(format, ##__VA_ARGS__);		\
	printf("%s", folded ? ";" : "\n");	\
})

#define __maybe_unused __attribute__((unused))

/* For simple skel wrapper */
#define ___concat(a, b)			a ## b
#define ___apply(fn, n)			___concat(fn, n)
#define SKEL_OPEN()			___apply(SKEL_NAME, __open)()
#define SKEL_OPEN_AND_LOAD()		___apply(SKEL_NAME, __open_and_load)()
#define SKEL_OPEN_OPTS(opts_ptr)	___apply(SKEL_NAME, __open_opts)(opts_ptr)
#define SKEL_LOAD(skel)			___apply(SKEL_NAME, __load)(skel)
#define SKEL_ATTACH(skel)		___apply(SKEL_NAME, __attach)(skel)
#define SKEL_DETACH(skel)		___apply(SKEL_NAME, __detach)(skel)
#define SKEL_DESTROY(skel)		___apply(SKEL_NAME, __destroy)(skel)
#define DEFINE_SKEL_OBJECT(name)	struct SKEL_NAME *name = NULL

static inline bool bpf_is_root()
{
	if (getuid()) {
		warning("Please run the tool as root - Exiting.\n");
		return false;
	} else
		return true;
}

static inline int get_pid_max(void)
{
	int pid_max;
	FILE *f;

	f = fopen("/proc/sys/kernel/pid_max", "r");
	if (!f)
		return -1;
	if (fscanf(f, "%d\n", &pid_max) != 1)
		pid_max = -1;
	fclose(f);
	return pid_max;
}

static inline int get_pid_maxlen(void)
{
	int pid_max_fd, pid_maxlen;
	char buf[256];

	pid_max_fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	pid_maxlen = read(pid_max_fd, buf, sizeof(buf)) - 1;

	close(pid_max_fd);

	return max(6, pid_maxlen);
}

static inline const char *get_uid_name(pid_t uid)
{
	struct passwd *passwd;

	passwd = getpwuid(uid);
	if (!passwd) {
		warning("getpwuid() failed: %s\n", strerror(errno));
		return NULL;
	}

	return passwd->pw_name;
}

static inline double time_since_start(void)
{
	long nsec, sec;
	static struct timespec start_time;
	static struct timespec current_time;
	static bool first = true;

	if (first) {
		clock_gettime(CLOCK_MONOTONIC, &start_time);
		first = false;
		return 0.0;
	}

	clock_gettime(CLOCK_MONOTONIC, &current_time);
	nsec = current_time.tv_nsec - start_time.tv_nsec;
	sec = current_time.tv_sec - start_time.tv_sec;
	if (nsec < 0) {
		nsec += NSEC_PER_SEC;
		sec--;
	}

	return sec + (double)nsec / NSEC_PER_SEC;
}

static inline __maybe_unused
const char *strftime_now(char *s, size_t max, const char *format)
{
	struct tm *tm;
	time_t t;

	t = time(NULL);
	tm = localtime(&t);
	if (!tm) {
		warning("localtime: %s\n", strerror(errno));
		return "<failed>";
	}
	if (!strftime(s, max, format, tm)) {
		warning("strftime error\n");
		return "<failed>";
	}

	return s;
}

static inline __maybe_unused long
safe_strtol(const char *str, long min, long max, const struct argp_state *state)
{
	long rval;
	char *endstr;

	errno = 0;
	rval = strtol(str, &endstr, 10);

	if ((errno == ERANGE && (rval == LONG_MAX || rval == LONG_MIN)) ||
	    (errno != 0 && rval == 0)) {
		warning("strtol(%s) failed\n", str);
		argp_usage(state);
		return rval;
	}

	if (endstr == str || (*endstr != '\0' && *endstr != '\n')) {
		warning("strtol(%s): Invalid value\n", str);
		argp_usage(state);
		return 0;
	}

	if (rval > max || rval < min) {
		warning("strtol(%s): %ld is out of range %ld - %ld\n", str, rval, min, max);
		argp_usage(state);
		return 0;
	}

	return rval;
}

static inline __maybe_unused unsigned long
safe_strtoul(const char *str, unsigned long min, unsigned long max,
	     const struct argp_state *state)
{
	unsigned long rval;
	char *endstr;

	errno = 0;
	rval = strtoul(str, &endstr, 10);

	if ((errno == ERANGE && rval == ULONG_MAX) ||
	    (errno != 0 && rval == 0)) {
		warning("strtoul(%s) failed\n", str);
		argp_usage(state);
		return rval;
	}

	if (endstr == str || (*endstr != '\0' && *endstr != '\n')) {
		warning("strtoul(%s): Invalid value\n", str);
		argp_usage(state);
		return 0;
	}

	if (rval > max || rval < min) {
		warning("strtoul(%s): %lu is out of range %lu - %lu\n", str, rval, min, max);
		argp_usage(state);
		return 0;
	}

	return rval;
}

static inline __maybe_unused
long argp_parse_long(int key, const char *arg, const struct argp_state *state)
{
	long temp;

	if (!arg) {
		warning("Arg is NULL\n");
		argp_usage(state);
	}

	errno = 0;
	temp = strtol(arg, NULL, 10);
	if (errno || temp < 0) {
		warning("Error arg: %c : %s\n", (char)key, arg);
		argp_usage(state);
	}

	return temp;
}

static inline __maybe_unused
float argp_parse_float(int key, const char *arg, const struct argp_state *state)
{
	float temp;

	if (!arg) {
		warning("Arg is NULL\n");
		argp_usage(state);
	}

	errno = 0;
	temp = strtof(arg, NULL);
	if (errno || temp < 0) {
		warning("Error arg: %c : %s\n", (char)key, arg);
		argp_usage(state);
	}

	return temp;
}

static inline bool do_process_running(int pid)
{
	bool ret = kill(pid, 0);

	if (ret)
		warning("PID %d is not running.\n", pid);

	return !ret;
}

static inline __maybe_unused
long argp_parse_pid(int key, const char *arg, const struct argp_state *state)
{
	long pid = argp_parse_long(key, arg, state);

	if (!do_process_running(pid))
		argp_usage(state);

	return pid;
}

/* https://www.gnu.org/software/gnulib/manual/html_node/strerrorname_005fnp.html */
#if !defined(__GLIBC__) || __GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 32)
static inline const char *strerrorname_np(int errnum)
{
	switch (errnum) {
#ifdef E2BIG
	case E2BIG: return "E2BIG";
#endif
#ifdef EACCES
	case EACCES: return "EACCES";
#endif
#ifdef EADDRINUSE
	case EADDRINUSE: return "EADDRINUSE";
#endif
#ifdef EADDRNOTAVAIL
	case EADDRNOTAVAIL: return "EADDRNOTAVAIL";
#endif
#ifdef EADI
	case EADI: return "EADI";
#endif
#ifdef EADV
	case EADV: return "EADV";
#endif
#ifdef EAFNOSUPPORT
	case EAFNOSUPPORT: return "EAFNOSUPPORT";
#endif
#ifdef EAGAIN
	case EAGAIN: return "EAGAIN";
#endif
#ifdef EAIO
	case EAIO: return "EAIO";
#endif
#ifdef EALIGN
	case EALIGN: return "EALIGN";
#endif
#ifdef EALREADY
	case EALREADY: return "EALREADY";
#endif
#ifdef EASYNC
	case EASYNC: return "EASYNC";
#endif
#ifdef EAUTH
	case EAUTH: return "EAUTH";
#endif
#ifdef EBADARCH
	case EBADARCH: return "EBADARCH";
#endif
#ifdef EBADE
	case EBADE: return "EBADE";
#endif
#ifdef EBADEXEC
	case EBADEXEC: return "EBADEXEC";
#endif
#ifdef EBADF
	case EBADF: return "EBADF";
#endif
#ifdef EBADFD
	case EBADFD: return "EBADFD";
#endif
#ifdef EBADMACHO
	case EBADMACHO: return "EBADMACHO";
#endif
#ifdef EBADMSG
	case EBADMSG: return "EBADMSG";
#endif
#ifdef EBADR
	case EBADR: return "EBADR";
#endif
#ifdef EBADRPC
	case EBADRPC: return "EBADRPC";
#endif
#ifdef EBADRQC
	case EBADRQC: return "EBADRQC";
#endif
#ifdef EBADSLT
	case EBADSLT: return "EBADSLT";
#endif
#ifdef EBADVER
	case EBADVER: return "EBADVER";
#endif
#ifdef EBFONT
	case EBFONT: return "EBFONT";
#endif
#ifdef EBUSY
	case EBUSY: return "EBUSY";
#endif
#ifdef ECANCELED
	case ECANCELED: return "ECANCELED";
#endif
#if defined(ECANCELLED) && (!defined(ECANCELED) || ECANCELLED != ECANCELED)
	case ECANCELLED: return "ECANCELLED";
#endif
#ifdef ECAPMODE
	case ECAPMODE: return "ECAPMODE";
#endif
#ifdef ECHILD
	case ECHILD: return "ECHILD";
#endif
#ifdef ECHRNG
	case ECHRNG: return "ECHRNG";
#endif
#ifdef ECKPT
	case ECKPT: return "ECKPT";
#endif
#ifdef ECLONEME
	case ECLONEME: return "ECLONEME";
#endif
#ifdef ECOMM
	case ECOMM: return "ECOMM";
#endif
#ifdef ECONFIG
	case ECONFIG: return "ECONFIG";
#endif
#ifdef ECONNABORTED
	case ECONNABORTED: return "ECONNABORTED";
#endif
#ifdef ECONNREFUSED
	case ECONNREFUSED: return "ECONNREFUSED";
#endif
#ifdef ECONNRESET
	case ECONNRESET: return "ECONNRESET";
#endif
#ifdef ECORRUPT
	case ECORRUPT: return "ECORRUPT";
#endif
#ifdef ECVCERORR
	case ECVCERORR: return "ECVCERORR";
#endif
#ifdef ECVPERORR
	case ECVPERORR: return "ECVPERORR";
#endif
#ifdef EDEADLK
	case EDEADLK: return "EDEADLK";
#endif
#if defined(EDEADLOCK) && (!defined(EDEADLK) || EDEADLOCK != EDEADLK)
	case EDEADLOCK: return "EDEADLOCK";
#endif
#ifdef EDESTADDREQ
	case EDESTADDREQ: return "EDESTADDREQ";
#endif
#ifdef EDESTADDRREQ
	case EDESTADDRREQ: return "EDESTADDRREQ";
#endif
#ifdef EDEVERR
	case EDEVERR: return "EDEVERR";
#endif
#ifdef EDIRIOCTL
	case EDIRIOCTL: return "EDIRIOCTL";
#endif
#ifdef EDIRTY
	case EDIRTY: return "EDIRTY";
#endif
#ifdef EDIST
	case EDIST: return "EDIST";
#endif
#ifdef EDOM
	case EDOM: return "EDOM";
#endif
#ifdef EDOOFUS
	case EDOOFUS: return "EDOOFUS";
#endif
#ifdef EDOTDOT
	case EDOTDOT: return "EDOTDOT";
#endif
#ifdef EDQUOT
	case EDQUOT: return "EDQUOT";
#endif
#ifdef EDUPFD
	case EDUPFD: return "EDUPFD";
#endif
#ifdef EDUPPKG
	case EDUPPKG: return "EDUPPKG";
#endif
#ifdef EEXIST
	case EEXIST: return "EEXIST";
#endif
#ifdef EFAIL
	case EFAIL: return "EFAIL";
#endif
#ifdef EFAULT
	case EFAULT: return "EFAULT";
#endif
#ifdef EFBIG
	case EFBIG: return "EFBIG";
#endif
#ifdef EFORMAT
	case EFORMAT: return "EFORMAT";
#endif
#ifdef EFSCORRUPTED
	case EFSCORRUPTED: return "EFSCORRUPTED";
#endif
#ifdef EFTYPE
	case EFTYPE: return "EFTYPE";
#endif
#ifdef EHOSTDOWN
	case EHOSTDOWN: return "EHOSTDOWN";
#endif
#ifdef EHOSTUNREACH
	case EHOSTUNREACH: return "EHOSTUNREACH";
#endif
#ifdef EHWPOISON
	case EHWPOISON: return "EHWPOISON";
#endif
#ifdef EIDRM
	case EIDRM: return "EIDRM";
#endif
#ifdef EILSEQ
	case EILSEQ: return "EILSEQ";
#endif
#ifdef EINIT
	case EINIT: return "EINIT";
#endif
#ifdef EINPROG
	case EINPROG: return "EINPROG";
#endif
#ifdef EINPROGRESS
	case EINPROGRESS: return "EINPROGRESS";
#endif
#ifdef EINTEGRITY
	case EINTEGRITY: return "EINTEGRITY";
#endif
#ifdef EINTR
	case EINTR: return "EINTR";
#endif
#ifdef EINVAL
	case EINVAL: return "EINVAL";
#endif
#ifdef EIO
	case EIO: return "EIO";
#endif
#ifdef EIPSEC
	case EIPSEC: return "EIPSEC";
#endif
#ifdef EISCONN
	case EISCONN: return "EISCONN";
#endif
#ifdef EISDIR
	case EISDIR: return "EISDIR";
#endif
#ifdef EISNAM
	case EISNAM: return "EISNAM";
#endif
#ifdef EJUSTRETURN
	case EJUSTRETURN: return "EJUSTRETURN";
#endif
#ifdef EKEEPLOOKING
	case EKEEPLOOKING: return "EKEEPLOOKING";
#endif
#ifdef EKEYEXPIRED
	case EKEYEXPIRED: return "EKEYEXPIRED";
#endif
#ifdef EKEYREJECTED
	case EKEYREJECTED: return "EKEYREJECTED";
#endif
#ifdef EKEYREVOKED
	case EKEYREVOKED: return "EKEYREVOKED";
#endif
#ifdef EL2HLT
	case EL2HLT: return "EL2HLT";
#endif
#ifdef EL2NSYNC
	case EL2NSYNC: return "EL2NSYNC";
#endif
#ifdef EL3HLT
	case EL3HLT: return "EL3HLT";
#endif
#ifdef EL3RST
	case EL3RST: return "EL3RST";
#endif
#ifdef ELIBACC
	case ELIBACC: return "ELIBACC";
#endif
#ifdef ELIBBAD
	case ELIBBAD: return "ELIBBAD";
#endif
#ifdef ELIBEXEC
	case ELIBEXEC: return "ELIBEXEC";
#endif
#ifdef ELIBMAX
	case ELIBMAX: return "ELIBMAX";
#endif
#ifdef ELIBSCN
	case ELIBSCN: return "ELIBSCN";
#endif
#ifdef ELNRNG
	case ELNRNG: return "ELNRNG";
#endif
#ifdef ELOCKUNMAPPED
	case ELOCKUNMAPPED: return "ELOCKUNMAPPED";
#endif
#ifdef ELOOP
	case ELOOP: return "ELOOP";
#endif
#ifdef EMEDIA
	case EMEDIA: return "EMEDIA";
#endif
#ifdef EMEDIUMTYPE
	case EMEDIUMTYPE: return "EMEDIUMTYPE";
#endif
#ifdef EMFILE
	case EMFILE: return "EMFILE";
#endif
#ifdef EMLINK
	case EMLINK: return "EMLINK";
#endif
#ifdef EMOUNTEXIT
	case EMOUNTEXIT: return "EMOUNTEXIT";
#endif
#ifdef EMOVEFD
	case EMOVEFD: return "EMOVEFD";
#endif
#ifdef EMSGSIZE
	case EMSGSIZE: return "EMSGSIZE";
#endif
#ifdef EMTIMERS
	case EMTIMERS: return "EMTIMERS";
#endif
#ifdef EMULTIHOP
	case EMULTIHOP: return "EMULTIHOP";
#endif
#ifdef ENAMETOOLONG
	case ENAMETOOLONG: return "ENAMETOOLONG";
#endif
#ifdef ENAVAIL
	case ENAVAIL: return "ENAVAIL";
#endif
#ifdef ENEEDAUTH
	case ENEEDAUTH: return "ENEEDAUTH";
#endif
#ifdef ENETDOWN
	case ENETDOWN: return "ENETDOWN";
#endif
#ifdef ENETRESET
	case ENETRESET: return "ENETRESET";
#endif
#ifdef ENETUNREACH
	case ENETUNREACH: return "ENETUNREACH";
#endif
#ifdef ENFILE
	case ENFILE: return "ENFILE";
#endif
#ifdef ENFSREMOTE
	case ENFSREMOTE: return "ENFSREMOTE";
#endif
#ifdef ENOANO
	case ENOANO: return "ENOANO";
#endif
#ifdef ENOATTR
	case ENOATTR: return "ENOATTR";
#endif
#ifdef ENOBUFS
	case ENOBUFS: return "ENOBUFS";
#endif
#ifdef ENOCONNECT
	case ENOCONNECT: return "ENOCONNECT";
#endif
#ifdef ENOCSI
	case ENOCSI: return "ENOCSI";
#endif
#ifdef ENODATA
	case ENODATA: return "ENODATA";
#endif
#ifdef ENODEV
	case ENODEV: return "ENODEV";
#endif
#ifdef ENOENT
	case ENOENT: return "ENOENT";
#endif
#ifdef ENOEXEC
	case ENOEXEC: return "ENOEXEC";
#endif
#ifdef ENOIOCTL
	case ENOIOCTL: return "ENOIOCTL";
#endif
#ifdef ENOKEY
	case ENOKEY: return "ENOKEY";
#endif
#ifdef ENOLCK
	case ENOLCK: return "ENOLCK";
#endif
#ifdef ENOLINK
	case ENOLINK: return "ENOLINK";
#endif
#ifdef ENOLOAD
	case ENOLOAD: return "ENOLOAD";
#endif
#ifdef ENOMATCH
	case ENOMATCH: return "ENOMATCH";
#endif
#ifdef ENOMEDIUM
	case ENOMEDIUM: return "ENOMEDIUM";
#endif
#ifdef ENOMEM
	case ENOMEM: return "ENOMEM";
#endif
#ifdef ENOMSG
	case ENOMSG: return "ENOMSG";
#endif
#ifdef ENONET
	case ENONET: return "ENONET";
#endif
#ifdef ENOPKG
	case ENOPKG: return "ENOPKG";
#endif
#ifdef ENOPOLICY
	case ENOPOLICY: return "ENOPOLICY";
#endif
#ifdef ENOPROTOOPT
	case ENOPROTOOPT: return "ENOPROTOOPT";
#endif
#ifdef ENOREG
	case ENOREG: return "ENOREG";
#endif
#ifdef ENOSPC
	case ENOSPC: return "ENOSPC";
#endif
#ifdef ENOSR
	case ENOSR: return "ENOSR";
#endif
#ifdef ENOSTR
	case ENOSTR: return "ENOSTR";
#endif
#ifdef ENOSYM
	case ENOSYM: return "ENOSYM";
#endif
#ifdef ENOSYS
	case ENOSYS: return "ENOSYS";
#endif
#ifdef ENOTACTIVE
	case ENOTACTIVE: return "ENOTACTIVE";
#endif
#ifdef ENOTBLK
	case ENOTBLK: return "ENOTBLK";
#endif
#ifdef ENOTCAPABLE
	case ENOTCAPABLE: return "ENOTCAPABLE";
#endif
#ifdef ENOTCONN
	case ENOTCONN: return "ENOTCONN";
#endif
#ifdef ENOTDIR
	case ENOTDIR: return "ENOTDIR";
#endif
#ifdef ENOTEMPTY
	case ENOTEMPTY: return "ENOTEMPTY";
#endif
#ifdef ENOTNAM
	case ENOTNAM: return "ENOTNAM";
#endif
#ifdef ENOTREADY
	case ENOTREADY: return "ENOTREADY";
#endif
#ifdef ENOTRECOVERABLE
	case ENOTRECOVERABLE: return "ENOTRECOVERABLE";
#endif
#ifdef ENOTRUST
	case ENOTRUST: return "ENOTRUST";
#endif
#ifdef ENOTSOCK
	case ENOTSOCK: return "ENOTSOCK";
#endif
#ifdef ENOTSUP
	case ENOTSUP: return "ENOTSUP";
#endif
#ifdef ENOTTY
	case ENOTTY: return "ENOTTY";
#endif
#ifdef ENOTUNIQ
	case ENOTUNIQ: return "ENOTUNIQ";
#endif
#ifdef ENOUNLD
	case ENOUNLD: return "ENOUNLD";
#endif
#ifdef ENOUNREG
	case ENOUNREG: return "ENOUNREG";
#endif
#ifdef ENXIO
	case ENXIO: return "ENXIO";
#endif
#ifdef EOPCOMPLETE
	case EOPCOMPLETE: return "EOPCOMPLETE";
#endif
#if defined(EOPNOTSUPP) && (!defined(ENOTSUP) || EOPNOTSUPP != ENOTSUP)
	case EOPNOTSUPP: return "EOPNOTSUPP";
#endif
#ifdef EOVERFLOW
	case EOVERFLOW: return "EOVERFLOW";
#endif
#ifdef EOWNERDEAD
	case EOWNERDEAD: return "EOWNERDEAD";
#endif
#ifdef EPASSTHROUGH
	case EPASSTHROUGH: return "EPASSTHROUGH";
#endif
#ifdef EPATHREMOTE
	case EPATHREMOTE: return "EPATHREMOTE";
#endif
#ifdef EPERM
	case EPERM: return "EPERM";
#endif
#ifdef EPFNOSUPPORT
	case EPFNOSUPPORT: return "EPFNOSUPPORT";
#endif
#ifdef EPIPE
	case EPIPE: return "EPIPE";
#endif
#ifdef EPOWERF
	case EPOWERF: return "EPOWERF";
#endif
#ifdef EPROCLIM
	case EPROCLIM: return "EPROCLIM";
#endif
#ifdef EPROCUNAVAIL
	case EPROCUNAVAIL: return "EPROCUNAVAIL";
#endif
#ifdef EPROGMISMATCH
	case EPROGMISMATCH: return "EPROGMISMATCH";
#endif
#ifdef EPROGUNAVAIL
	case EPROGUNAVAIL: return "EPROGUNAVAIL";
#endif
#ifdef EPROTO
	case EPROTO: return "EPROTO";
#endif
#ifdef EPROTONOSUPPORT
	case EPROTONOSUPPORT: return "EPROTONOSUPPORT";
#endif
#ifdef EPROTOTYPE
	case EPROTOTYPE: return "EPROTOTYPE";
#endif
#ifdef EPWROFF
	case EPWROFF: return "EPWROFF";
#endif
#ifdef EQFULL
	case EQFULL: return "EQFULL";
#endif
#ifdef EQSUSPENDED
	case EQSUSPENDED: return "EQSUSPENDED";
#endif
#ifdef ERANGE
	case ERANGE: return "ERANGE";
#endif
#ifdef ERECYCLE
	case ERECYCLE: return "ERECYCLE";
#endif
#ifdef EREDRIVEOPEN
	case EREDRIVEOPEN: return "EREDRIVEOPEN";
#endif
#ifdef EREFUSED
	case EREFUSED: return "EREFUSED";
#endif
#ifdef ERELOC
	case ERELOC: return "ERELOC";
#endif
#ifdef ERELOCATED
	case ERELOCATED: return "ERELOCATED";
#endif
#ifdef ERELOOKUP
	case ERELOOKUP: return "ERELOOKUP";
#endif
#ifdef EREMCHG
	case EREMCHG: return "EREMCHG";
#endif
#ifdef EREMDEV
	case EREMDEV: return "EREMDEV";
#endif
#ifdef EREMOTE
	case EREMOTE: return "EREMOTE";
#endif
#ifdef EREMOTEIO
	case EREMOTEIO: return "EREMOTEIO";
#endif
#ifdef EREMOTERELEASE
	case EREMOTERELEASE: return "EREMOTERELEASE";
#endif
#ifdef ERESTART
	case ERESTART: return "ERESTART";
#endif
#ifdef ERFKILL
	case ERFKILL: return "ERFKILL";
#endif
#ifdef EROFS
	case EROFS: return "EROFS";
#endif
#ifdef ERPCMISMATCH
	case ERPCMISMATCH: return "ERPCMISMATCH";
#endif
#ifdef ESAD
	case ESAD: return "ESAD";
#endif
#ifdef ESHLIBVERS
	case ESHLIBVERS: return "ESHLIBVERS";
#endif
#ifdef ESHUTDOWN
	case ESHUTDOWN: return "ESHUTDOWN";
#endif
#ifdef ESOCKTNOSUPPORT
	case ESOCKTNOSUPPORT: return "ESOCKTNOSUPPORT";
#endif
#ifdef ESOFT
	case ESOFT: return "ESOFT";
#endif
#ifdef ESPIPE
	case ESPIPE: return "ESPIPE";
#endif
#ifdef ESRCH
	case ESRCH: return "ESRCH";
#endif
#ifdef ESRMNT
	case ESRMNT: return "ESRMNT";
#endif
#ifdef ESTALE
	case ESTALE: return "ESTALE";
#endif
#ifdef ESTART
	case ESTART: return "ESTART";
#endif
#ifdef ESTRPIPE
	case ESTRPIPE: return "ESTRPIPE";
#endif
#ifdef ESYSERROR
	case ESYSERROR: return "ESYSERROR";
#endif
#ifdef ETIME
	case ETIME: return "ETIME";
#endif
#ifdef ETIMEDOUT
	case ETIMEDOUT: return "ETIMEDOUT";
#endif
#ifdef ETOOMANYREFS
	case ETOOMANYREFS: return "ETOOMANYREFS";
#endif
#ifdef ETXTBSY
	case ETXTBSY: return "ETXTBSY";
#endif
#ifdef EUCLEAN
	case EUCLEAN: return "EUCLEAN";
#endif
#ifdef EUNATCH
	case EUNATCH: return "EUNATCH";
#endif
#ifdef EUSERS
	case EUSERS: return "EUSERS";
#endif
#ifdef EVERSION
	case EVERSION: return "EVERSION";
#endif
#if defined(EWOULDBLOCK) && (!defined(EAGAIN) || EWOULDBLOCK != EAGAIN)
	case EWOULDBLOCK: return "EWOULDBLOCK";
#endif
#ifdef EWRONGFS
	case EWRONGFS: return "EWRONGFS";
#endif
#ifdef EWRPROTECT
	case EWRPROTECT: return "EWRPROTECT";
#endif
#ifdef EXDEV
	case EXDEV: return "EXDEV";
#endif
#ifdef EXFULL
	case EXFULL: return "EXFULL";
#endif
	}
	return NULL;
}
#endif

static inline const char *strerrno(int errnum)
{
	const char *errstr;
	char string[32] = {};

	if (!errnum)
		return "0";

	string[0] = 0;
	errstr = strerrorname_np(-errnum);
	if (!errstr) {
		snprintf(string, sizeof(string), "%d", errnum);
		return strdup(string);
	}

	snprintf(string, sizeof(string), "-%s", errstr);
	return strdup(string);
}

static inline char *
find_library_so(const char *binary, const char *library)
{
	FILE *f;
	char *line = NULL;
	size_t line_sz;
	char *result = NULL;
	char path[128] = {};
	char command[128] = {};

	sprintf(command, "ldd %s", binary);
	f = popen(command, "r");
	if (!f)
		return NULL;

	while (getline(&line, &line_sz, f) >= 0) {
		if (sscanf(line, "%*s => %127s", path) < 1)
			continue;
		if (strstr(line, library)) {
			result = strdup(path);
			break;
		}
	}

	free(line);
	pclose(f);

	return result;
}

static inline const char *demangling_cplusplus_function(const char *name)
{
	char command[256] = {};
	FILE *f;
	char buf[128] = {};
	const char *ret;

	if (strncmp(name, "_Z", 2) && strncmp(name, "____Z", 5))
		return name;

	sprintf(command, "c++filt %s", name);
	f = popen(command, "r");
	if (!f)
		return name;

	if (fgets(buf, 128, f) != NULL) {
		/* drop '\n' */
		buf[strlen(buf) - 1] = 0;
		ret = strdup(buf);
	} else
		ret = name;

	pclose(f);
	return ret;
}

#define MAX_PATH_LENGTH 256
#define MAX_NAME_LENGTH 256

static inline int get_process_executable_name(pid_t pid, char *executable_name)
{
	char cmdline_path[MAX_PATH_LENGTH];
	snprintf(cmdline_path, MAX_PATH_LENGTH, "/proc/%d/cmdline", pid);

	FILE *fp = fopen(cmdline_path, "r");
	if (fp == NULL)
		return -1;

	char line[MAX_NAME_LENGTH];
	if (fgets(line, MAX_NAME_LENGTH, fp) != NULL) {
		char *name_start = line;
		char *token = strtok(line, " ");
		if (token)
			name_start = token;

		strncpy(executable_name, name_start, MAX_NAME_LENGTH);
		fclose(fp);
		return 0;
	}

	fclose(fp);
	return -1;
}

static inline const char *detect_language(int pid)
{
	const char *languages[] = {"java", "node", "perl", "php", "python", "ruby"};
	const char *language_c = "c";
	char procfilename[24], line[4096], pathname[32], *str;
	FILE *procfile;
	int i, ret;

	/* Look for clues in the absolute path to the executable. */
	snprintf(procfilename, sizeof(procfilename), "/proc/%ld/exe", (long)pid);
	if (realpath(procfilename, line)) {
		for (i = 0; i < ARRAY_SIZE(languages); i++)
			if (strstr(line, languages[i]))
				return languages[i];
	}

	snprintf(procfilename, sizeof(procfilename), "/proc/%ld/maps", (long)pid);
	procfile = fopen(procfilename, "r");
	if (!procfile)
		return NULL;

	/* Look for clues in memory mappings. */
	bool libc = false;
	do {
		char perm[8], dev[8];
		long long begin, end, size, inode;
		ret = fscanf(procfile, "%llx-%llx %s %llx %s %lld", &begin, &end, perm,
			     &size, dev, &inode);
		if (!fgets(line, sizeof(line), procfile))
			break;
		if (ret == 6) {
			char *mapname = line;
			char *newline = strchr(line, '\n');
			if (newline)
				newline[0] = '\0';
			while (isspace(mapname[0])) mapname++;
			for (i = 0; i < ARRAY_SIZE(languages); i++) {
				snprintf(pathname, sizeof(pathname), "/lib%s", languages[i]);
				if (strstr(mapname, pathname)) {
					fclose(procfile);
					return languages[i];
				}
				if ((str = strstr(mapname, "libc")) &&
				    (str[4] == '-' || str[4] == '.'))
					libc = true;
			}
		}
	} while (ret && ret != EOF);

	fclose(procfile);

	/* Return C as the language if libc was found and nothing else. */
	return libc ? language_c : NULL;
}

#endif
