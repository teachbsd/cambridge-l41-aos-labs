/*-
 * Copyright (c) 2015, 2020-2023 Robert N. M. Watson
 * Copyright (c) 2015 Bjoern A. Zeeb
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <net/if.h>

#include <netinet/in.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pmc.h>
#include <libxo/xo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include "ipc.h"
#include "pmc.h"

/*
 * Advanced Operating Systems1: Labs 2 and 3 - IPC and TCP.  This benchmark
 * pushes data through one of several choices of IPC (pipes, local domain
 * sockets, TCP sockets, shared memory) with various I/O parameters including
 * a configurable userspace buffer size, and in one of two modes (2thread,
 * 2proc).  It is able to capture timestamps, getrusage data, and performance
 * counter data on its behaviour (using Arm's A72 counter set).  And it can
 * print in text or JSON.
 */

unsigned int Bflag;		/* bare */
unsigned int gflag;		/* getrusage */
unsigned int jflag;		/* JSON */
unsigned int qflag;		/* quiet */
unsigned int sflag;		/* set socket-buffer sizes */
static unsigned int vflag;	/* verbose */

#define	LOOPBACK_IFNAME		"lo0"	/* Used only for informative output. */

/*
 * Which mode is the benchmark operating in?
 */
#define	BENCHMARK_MODE_INVALID_STRING	"invalid"
#define	BENCHMARK_MODE_2THREAD_STRING	"2thread"
#define	BENCHMARK_MODE_2PROC_STRING	"2proc"
#define	BENCHMARK_MODE_DESCRIBE_STRING	"describe"

#define	BENCHMARK_MODE_INVALID		-1
#define	BENCHMARK_MODE_2THREAD		2
#define	BENCHMARK_MODE_2PROC		3
#define	BENCHMARK_MODE_DESCRIBE		4

#define	BENCHMARK_MODE_DEFAULT		BENCHMARK_MODE_2THREAD
unsigned int benchmark_mode = BENCHMARK_MODE_DEFAULT;

#define	BENCHMARK_IPC_INVALID_STRING	"invalid"
#define	BENCHMARK_IPC_PIPE_STRING	"pipe"
#define	BENCHMARK_IPC_LOCAL_SOCKET_STRING	"local"
#define	BENCHMARK_IPC_TCP_SOCKET_STRING		"tcp"
#define	BENCHMARK_IPC_SHMEM_STRING		"shmem"

#define	BENCHMARK_IPC_INVALID		-1
#define	BENCHMARK_IPC_PIPE		1
#define	BENCHMARK_IPC_LOCAL_SOCKET	2
#define	BENCHMARK_IPC_TCP_SOCKET	3
#define	BENCHMARK_IPC_SHMEM		4

#define	BENCHMARK_IPC_DEFAULT		BENCHMARK_IPC_PIPE
unsigned int ipc_type = BENCHMARK_IPC_DEFAULT;

#define	BENCHMARK_TCP_PORT_DEFAULT	10141
unsigned short tcp_port = BENCHMARK_TCP_PORT_DEFAULT;

#define	BUFFERSIZE	(128 * 1024UL)
long buffersize = BUFFERSIZE;	/* I/O buffer size */

#define	ITERATIONS	(1)
long iterations = ITERATIONS;	/* Number of iterations */

#define	TOTALSIZE	(16 * 1024 * 1024UL)
long totalsize = TOTALSIZE;	/* total I/O size */

long msgcount;			/* Derived number of messages. */

#define	max(x, y)	((x) > (y) ? (x) : (y))
#define	min(x, y)	((x) < (y) ? (x) : (y))

int	__sys_clock_gettime(__clockid_t, struct timespec *ts);

static int
ipc_type_from_string(const char *string)
{

	if (strcmp(BENCHMARK_IPC_PIPE_STRING, string) == 0)
		return (BENCHMARK_IPC_PIPE);
	else if (strcmp(BENCHMARK_IPC_LOCAL_SOCKET_STRING, string) == 0)
		return (BENCHMARK_IPC_LOCAL_SOCKET);
	else if (strcmp(BENCHMARK_IPC_TCP_SOCKET_STRING, string) == 0)
		return (BENCHMARK_IPC_TCP_SOCKET);
	else if (strcmp(BENCHMARK_IPC_SHMEM_STRING, string) == 0)
		return (BENCHMARK_IPC_SHMEM);
	else
		return (BENCHMARK_IPC_INVALID);
}

static const char *
ipc_type_to_string(int type)
{

	switch (type) {
	case BENCHMARK_IPC_PIPE:
		return (BENCHMARK_IPC_PIPE_STRING);

	case BENCHMARK_IPC_LOCAL_SOCKET:
		return (BENCHMARK_IPC_LOCAL_SOCKET_STRING);

	case BENCHMARK_IPC_TCP_SOCKET:
		return (BENCHMARK_IPC_TCP_SOCKET_STRING);

	case BENCHMARK_IPC_SHMEM:
		return (BENCHMARK_IPC_SHMEM_STRING);

	default:
		return (BENCHMARK_IPC_INVALID_STRING);
	}
}

static int
benchmark_mode_from_string(const char *string)
{

	if (strcmp(BENCHMARK_MODE_2THREAD_STRING, string) == 0)
		return (BENCHMARK_MODE_2THREAD);
	else if (strcmp(BENCHMARK_MODE_2PROC_STRING, string) == 0)
		return (BENCHMARK_MODE_2PROC);
	else if (strcmp(BENCHMARK_MODE_DESCRIBE_STRING, string) == 0)
		return (BENCHMARK_MODE_DESCRIBE);
	else
		return (BENCHMARK_MODE_INVALID);
}

static const char *
benchmark_mode_to_string(int mode)
{

	switch (mode) {
	case BENCHMARK_MODE_2THREAD:
		return (BENCHMARK_MODE_2THREAD_STRING);

	case BENCHMARK_MODE_2PROC:
		return (BENCHMARK_MODE_2PROC_STRING);

	case BENCHMARK_MODE_DESCRIBE:
		return (BENCHMARK_MODE_DESCRIBE_STRING);

	default:
		return (BENCHMARK_MODE_INVALID_STRING);
	}
}

/*
 * Print usage message and exit.
 */
static void
usage(void)
{

	xo_error(
	    "%s [-Bgjqsv] [-b buffersize] [-i pipe|local|tcp] [-n iterations]\n"
	    "    [-p tcp_port]"
	    " [-P arch|dcache|instr|tlbmem]"
	    " [-t totalsize] mode\n", getprogname());
	xo_error("\n"
  "Modes (pick one - default %s):\n"
  "    2thread     IPC between two threads in one process\n"
  "    2proc       IPC between two threads in two different processes\n"
  "    describe    Describe the hardware, OS, and benchmark configurations\n"
  "\n"
  "Optional flags:\n"
  "    -B                       Run in bare mode: no preparatory activities\n"
  "    -g                       Enable getrusage(2) collection\n"
  "    -i pipe|local|tcp|shmem  Select pipe, local sockets, TCP, or shared memory\n"
  "                             (default: %s)\n"
  "    -j                       Output as JSON\n"
  "    -p tcp_port              Set TCP port number (default: %u)\n"
  "    -P arch|dcache|instr|tlbmem  Enable hardware performance counters\n"
  "    -q                      Just run the benchmark, don't print stuff out\n"
  "    -s                      Set send/receive socket-buffer sizes to buffersize\n"
  "    -v                      Provide a verbose benchmark description\n"
  "    -b buffersize           Specify the buffer size (default: %ld)\n"
  "    -n iterations           Specify the number of times to run (default: %ld)\n"
  "    -t totalsize            Specify the total I/O size (default: %ld)\n",
	    benchmark_mode_to_string(BENCHMARK_MODE_DEFAULT),
	    ipc_type_to_string(BENCHMARK_IPC_DEFAULT),
	    BENCHMARK_TCP_PORT_DEFAULT,
	    BUFFERSIZE, ITERATIONS, TOTALSIZE);
	xo_finish();
	exit(EX_USAGE);
}

/*
 * Query the loopback interface's MTU; a bit obscure, so in its own function.
 */
static int
loopback_mtu(void)
{
	struct ifreq ifr;
	int s;

	bzero(&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, LOOPBACK_IFNAME, sizeof(ifr.ifr_name));
	s = socket(PF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		xo_err(EX_OSERR, "socket");
	if (ioctl(s, SIOCGIFMTU, &ifr) < 0)
		xo_err(EX_OSERR, "ioctl");
	close(s);
	return (ifr.ifr_mtu);
}

static void
print_configuration(void)
{
	char buffer[80];
	int integer;
	unsigned long unsignedlong;
	unsigned long pagesizes[MAXPAGESIZES];
	long signedlong;
	size_t len;
	int i;

	xo_open_container("hardware_configuration");
	xo_emit("Hardware configuration:\n");

	/* hw.machine */
	len = sizeof(buffer);
	if (sysctlbyname("hw.machine", buffer, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "sysctlbyname: hw.machine");
	buffer[sizeof(buffer)-1] = '\0';
	xo_emit("  hw.machine: {:hw.machine/%s}\n", buffer);

	/* hw.model */
	len = sizeof(buffer);
	if (sysctlbyname("hw.model", buffer, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "sysctlbyname: hw.model");
	buffer[sizeof(buffer)-1] = '\0';
	xo_emit("  hw.model: {:hw.model/%s}\n", buffer);

	/* hw.ncpu */
	len = sizeof(integer);
	if (sysctlbyname("hw.ncpu", &integer, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "sysctlbyname: hw.ncpu");
	xo_emit("  hw.ncpu: {:hw.ncpu/%d}\n", integer);

	/* hw.physmem */
	len = sizeof(unsignedlong);
	if (sysctlbyname("hw.physmem", &unsignedlong, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "sysctlbyname: hw.physmem");
	xo_emit("  hw.physmem: {:hw.physmem/%lu}\n", unsignedlong);

	/* hw.pagesizes */
	len = sizeof(pagesizes);
	if (sysctlbyname("hw.pagesizes", &pagesizes, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "sysctlbyname: hw.pagesizes");
	if (len < sizeof(pagesizes[0]))
		xo_err(EX_OSERR, "sysctlbyname: hwpagesizes unexpected size");
	xo_open_list("hw.pagesizes");
	xo_open_instance("pagesize");
	xo_emit("  hw.pagesizes: {:pagesize/%lu}", pagesizes[0]);
	xo_close_instance("pagesize");
	for (i = 1; i < len/sizeof(pagesizes[0]); i++) {
		xo_open_instance("pagesize");
		xo_emit(", {:pagesize/%lu}", pagesizes[i]);
		xo_close_instance("pagesize");
	}
	xo_emit("\n");
	xo_close_list("hw.pagesizes");

	/* hw.cpufreq.arm_freq */
	len = sizeof(integer);
	if (sysctlbyname("hw.cpufreq.arm_freq", &integer, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "sysctlbyname: hw.cpufreq.arm_freq");
	xo_emit("  hw.cpufreq.arm_freq: {:hw.cpufreq.arm_freq/%lu}\n",
	    integer);

	xo_close_container("hardware_configuration");
	xo_open_container("os_configuration");
	xo_emit("OS configuration:\n");

	/* kern.ostype */
	len = sizeof(buffer);
	if (sysctlbyname("kern.ostype", buffer, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "sysctlbyname: kern.ostype");
	buffer[sizeof(buffer)-1] = '\0';
	xo_emit("  kern.ostype: {:kern.ostype/%s}\n", buffer);

	/* kern.osrelease */
	len = sizeof(buffer);
	if (sysctlbyname("kern.osrelease", buffer, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "sysctlbyname: kern.osrelease");
	buffer[sizeof(buffer)-1] = '\0';
	xo_emit("  kern.osrelease: {:kern.osrelease/%s}\n", buffer);

	/* kern.ident */
	len = sizeof(buffer);
	if (sysctlbyname("kern.ident", buffer, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "sysctlbyname: kern.ident");
	buffer[sizeof(buffer)-1] = '\0';
	xo_emit("  kern.ident: {:kern.ident/%s}\n", buffer);

	/* Hostname */
	if (gethostname(buffer, sizeof(buffer)) < 0)
		xo_err(EX_OSERR, "gethostname");
	xo_emit("  kern.hostname: {:kern.hostname/%s}\n", buffer);

	/*
	 * For the following network/IPC-related bits of information, we turn
	 * to global settings rather than querying the specific socket/route/
	 * etc.  This is fine in our teaching environment, but is arguably not
	 * generalisable.
	 */

	xo_close_container("os_configuration");
	xo_open_container("network_ipc_configuration");
	xo_emit("Network and IPC configuration:\n");

	/* kern.ipc.pipe_mindirect */
	len = sizeof(signedlong);
	if (sysctlbyname("kern.ipc.pipe_mindirect", &signedlong, &len, NULL,
	    0) < 0)
		xo_err(EX_OSERR, "sysctlbyname: kern.ipc.pipe_mindirect");
	xo_emit("  kern.ipc.pipe_mindirect: {:kern.ipc.pipe_mindirect/%ld}\n",
	    signedlong);

	/* kern.ipc.maxsockbuf */
	len = sizeof(unsignedlong);
	if (sysctlbyname("kern.ipc.maxsockbuf", &unsignedlong, &len, NULL, 0)
	    < 0)
		xo_err(EX_OSERR, "sysctlbyname: kern.ipc.maxsockbuf");
	xo_emit("  kern.ipc.maxsockbuf: {:kern.ipc.maxsockbuf/%lu}\n",
	    unsignedlong);

	/* Hard-coded ifnet name. */
	xo_emit("  ifnet.name: {:ifnet.name/%s}\n", LOOPBACK_IFNAME);

	/* Loopback MTU. */
	xo_emit("  ifnet.mtu: {:ifnet.mtu/%u}\n", loopback_mtu());

	/* Default TCP congestion-control algorithm. */
	len = sizeof(buffer);
	if (sysctlbyname("net.inet.tcp.cc.algorithm", buffer, &len, NULL, 0) <
	    0)
		xo_err(EX_OSERR, "sysctlbyname: net.inet.tcp.cc.algorithm");
	buffer[sizeof(buffer)-1] = '\0';
	xo_emit("  net.inet.tcp.cc.algorithm: "
	    "{:net.inet.tcp.cc.algorithm/%s}\n", buffer);

	/* Netisr threads pinned? */
	len = sizeof(integer);
	if (sysctlbyname("net.isr.bindthreads", &integer, &len, NULL, 0) < 0)
		xo_err(EX_OSERR, "sysctlbyname: net.isr.bindthreads");
	xo_emit("  net.isr.bindthreads: {:net.isr.bindthreads/%d}\n",
	    integer);

	/* Netisr queue length. */
	len = sizeof(integer);
	if (sysctlbyname("net.isr.defaultqlimit", &integer, &len, NULL, 0) <
	    0)
		xo_err(EX_OSERR, "sysctlbyname: net.isr.defaultqlimit");
	xo_emit("  net.isr.defaultqlimit: {:net.isr.defaultqlimit/%d}\n",
	    integer);
	xo_close_container("network_ipc_configuration");

	xo_open_container("benchmark_configuration");
	xo_emit("Benchmark configuration:\n");
	xo_emit("  buffersize: {:buffersize/%ld}\n", buffersize);
	xo_emit("  totalsize: {:totalsize/%ld}\n", totalsize);
	xo_emit("  msgcount: {:msgcount/%ld}\n", msgcount);
	xo_emit("  mode: {:mode/%s}\n",
	    benchmark_mode_to_string(benchmark_mode));
	xo_emit("  ipctype: {:ipctype/%s}\n",
	    ipc_type_to_string(ipc_type));
	xo_emit("  pmctype: {:pmctype/%s}\n",
	    benchmark_pmc_to_string(benchmark_pmc));
	xo_emit("  iterations: {:iterations/%ld}\n", iterations);
	xo_close_container("benchmark_configuration");

	xo_flush();
}

/*
 * main(): parse arguments, invoke benchmark function.
 */
int
main(int argc, char *argv[])
{
	char *endp;
	long l;
	int ch;

	argc = xo_parse_args(argc, argv);
	if (argc < 0)
		exit(EX_USAGE);

	buffersize = BUFFERSIZE;
	totalsize = TOTALSIZE;
	while ((ch = getopt(argc, argv, "Bb:gi:jn:p:P:qst:vP:")) != -1) {
		switch (ch) {
		case 'B':
			Bflag++;
			break;

		case 'b':
			buffersize = strtol(optarg, &endp, 10);
			if (*optarg == '\0' || *endp != '\0' || buffersize <= 0)
				usage();
			break;

		case 'i':
			ipc_type = ipc_type_from_string(optarg);
			if (ipc_type == BENCHMARK_IPC_INVALID)
				usage();
			break;

		case 'j':
			jflag++;
			xo_set_style(NULL, XO_STYLE_JSON);
			xo_set_flags(NULL, XOF_PRETTY);
			break;

		case 'n':
			iterations = strtol(optarg, &endp, 10);
			if (*optarg == '\0' || *endp != '\0' || iterations <= 0)
				usage();
			break;

		case 'p':
			l = strtol(optarg, &endp, 10);
			if (*optarg == '\0' || *endp != '\0' ||
			    l <= 0 || l > 65535)
				usage();
			tcp_port = l;
			break;

		case 'P':
			benchmark_pmc = benchmark_pmc_from_string(optarg);
			if (benchmark_pmc == BENCHMARK_PMC_INVALID)
				usage();
			break;
		case 'g':
			gflag++;
			break;

		case 'q':
			qflag++;
			break;

		case 's':
			sflag++;
			break;

		case 't':
			totalsize = strtol(optarg, &endp, 10);
			if (*optarg == '\0' || *endp != '\0' || totalsize <= 0)
				usage();
			break;

		case 'v':
			vflag++;
			break;

		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/*
	 * A little argument-specific validation.
	 */
	if (sflag && (ipc_type != BENCHMARK_IPC_LOCAL_SOCKET) &&
	    (ipc_type != BENCHMARK_IPC_TCP_SOCKET))
		usage();

	/*
	 * Exactly one of our operational modes, which will be specified as
	 * the next (and only) mandatory argument.
	 */
	if (argc != 1)
		usage();
	benchmark_mode = benchmark_mode_from_string(argv[0]);
	if (benchmark_mode == BENCHMARK_MODE_INVALID)
		usage();
	if (benchmark_mode == BENCHMARK_MODE_DESCRIBE)
		vflag = 1;

	if (totalsize % buffersize != 0)
		xo_errx(EX_USAGE, "FAIL: data size (%ld) is not a multiple "
		    "of buffersize (%ld)", totalsize, buffersize);
	msgcount = totalsize / buffersize;
	if (msgcount < 0)
		xo_errx(EX_USAGE, "FAIL: negative block count");

	/*
	 * Configuration information first, if requested (but only once).
	 */
	if (!qflag && vflag)
		print_configuration();
	if (benchmark_mode != BENCHMARK_MODE_DESCRIBE)
		ipc();
	exit(0);
}
