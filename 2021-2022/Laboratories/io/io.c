/*-
 * Copyright (c) 2015, 2020-2021 Robert N. M. Watson
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
#include <sys/cpuset.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/sysctl.h>
#include <sys/resource.h>
#include <sys/time.h>

#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <libxo/xo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

/*
 * L41: Lab 1 - I/O tracing
 *
 * This simplistic I/O benchmark simply opens a file or device and performs a
 * series of read() or write() I/Os to it.  It times and optionally presents a
 * few summary notes and statistics.
 */

#define	BLOCKSIZE	(16 * 1024UL)
#define	ITERATIONS	(1)
#define	TOTALSIZE	(16 * 1024 * 1024UL)

static unsigned int Bflag;	/* bare */
static unsigned int dflag;	/* O_DIRECT */
static unsigned int gflag;	/* getrusage */
static unsigned int qflag;	/* quiet */
static unsigned int sflag;	/* fsync() */
static unsigned int vflag;	/* verbose */

const char *operation_string;	/* "create", "read", or "write" */

#define	OPERATION_INVALID_STRING	"invalid"
#define	OPERATION_NONE_STRING		"none"
#define	OPERATION_CREATE_STRING		"create"
#define	OPERATION_DESCRIBE_STRING	"describe"
#define	OPERATION_READ_STRING		"read"
#define	OPERATION_WRITE_STRING		"write"

#define	OPERATION_INVALID		-1
#define	OPERATION_NONE			0
#define	OPERATION_CREATE		1
#define	OPERATION_DESCRIBE		2
#define	OPERATION_READ			3
#define	OPERATION_WRITE			4

static int operation = OPERATION_INVALID;

static long buffersize;		/* I/O buffer size */
static long iterations;		/* number of iterations  to perform */
static long totalsize;		/* total I/O size; multiple of buffer size */
static long blockcount;		/* derived number of blocks. */

int	__sys_clock_gettime(__clockid_t, struct timespec *ts);

/*
 * Print usage message and exit.
 */
static void
usage(void)
{

	xo_error("usage: %s [-Bdjqsv] [-b buffersize] [-n iterations] "
	   "[-t totalsize]\n"
	   "    create|describe|read|write path\n", PROGNAME);
	xo_error("\n"
  "Modes:\n"
  "    create      Create the specified I/O data file\n"
  "    describe    Describe the hardware, OS, and benchmark configurations\n"
  "    read        Perform the read benchmark variant\n"
  "    write       Perform the write benchmark variant\n"
  "\n"
  "Optional flags:\n"
  "    -B              Run in bare mode: no preparatory activities\n"
  "    -d              Set O_DIRECT flag to bypass buffer cache\n"
  "    -g              Enable getrusage(2) collection\n"
  "    -j              Output as JSON\n"
  "    -q              Just run the benchmark, don't print stuff out\n"
  "    -s              Call fsync() on the file descriptor when complete\n"
  "    -v              Provide a verbose benchmark description\n"
  "    -b buffersize   Specify the buffer size (default: %ld)\n"
  "    -n iterations   Specify the number of times to run (default: %ld)\n"
  "    -t totalsize    Specify the total I/O size (default: %ld)\n",
	    BLOCKSIZE, ITERATIONS, TOTALSIZE);
	xo_finish();
	exit(EX_USAGE);
}

static int
operation_from_string(const char *operation_string)
{

	if (strcmp(operation_string, OPERATION_NONE_STRING) == 0)
		return (OPERATION_NONE);
	else if (strcmp(operation_string, OPERATION_CREATE_STRING) == 0)
		return (OPERATION_CREATE);
	else if (strcmp(operation_string, OPERATION_DESCRIBE_STRING) == 0)
		return (OPERATION_DESCRIBE);
	else if (strcmp(operation_string, OPERATION_READ_STRING) == 0)
		return (OPERATION_READ);
	else if (strcmp(operation_string, OPERATION_WRITE_STRING) == 0)
		return (OPERATION_WRITE);
	else
		return (OPERATION_INVALID);
}

static const char *
operation_to_string(int operation_number)
{

	switch (operation_number) {
	case OPERATION_NONE:
		return (OPERATION_NONE_STRING);

	case OPERATION_CREATE:
		return (OPERATION_CREATE_STRING);

	case OPERATION_DESCRIBE:
		return (OPERATION_DESCRIBE_STRING);

	case OPERATION_READ:
		return (OPERATION_READ_STRING);

	case OPERATION_WRITE:
		return (OPERATION_WRITE_STRING);

	default:
		return (OPERATION_INVALID_STRING);
	}
}

static void
print_configuration(const char *path)
{
	struct statfs statfs_buf;
	char buffer[80], *bufferp;
	int integer;
	unsigned long unsignedlong;
	unsigned long pagesizes[MAXPAGESIZES];
	size_t len;
	int i;

	xo_open_container("hw_configuration");
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
		xo_err(EX_OSERR, "sysctlbyname: hwpagesizes unexpectes size");
	xo_open_list("hw.pagesizes");
	xo_open_instance("pagesize");
	xo_emit("  hw.pagesizes: {:pagesize/%ld}", pagesizes[0]);
	xo_close_instance("pagesize");
	for (i = 1; i < len/sizeof(pagesizes[0]); i++) {
		xo_open_instance("pagesize");
		xo_emit(", {:pagesize/%ld}", pagesizes[i]);
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

	xo_close_container("hw_configuration");
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

	/* Disk and filesystem information */
	strlcpy(buffer, path, sizeof(buffer));
	bufferp = dirname(buffer);
	if (statfs(bufferp, &statfs_buf) < 0)
		xo_err(EX_OSERR, "statfs");
	xo_emit("  fstype: {:fstype/%s}\n", statfs_buf.f_fstypename);
	xo_emit("  fsdev: {:fsdev/%s}\n", statfs_buf.f_mntfromname);
	xo_emit("  fspath: {:fspath/%s}\n", statfs_buf.f_mntonname);
	xo_close_container("os_configuration");

	xo_open_container("benchmark_configuration");
	xo_emit("Benchmark configuration:\n");
	xo_emit("  buffersize: {:buffersize/%ld}\n", buffersize);
	xo_emit("  totalsize: {:totalsize/%ld}\n", totalsize);
	xo_emit("  blockcount: {:blockcount/%ld}\n", blockcount);
	xo_emit("  operation: {:operation/%s}\n",
	    operation_to_string(operation));
	xo_emit("  path: {:path/%s}\n", path);
	xo_emit("  iterations: {:iterations/%ld}\n", iterations);
	xo_close_container("benchmark_configuration");

	xo_flush();
}

/*
 * The I/O benchmark itself.  Perform any necessary setup.  Open the file or
 * device.  Take a timestamp.  Perform the work.  Take another timestamp.
 * (Optionally) print the results.  (n) times.
 */
static void
io(const char *path)
{
	struct rusage rusage_self_before, rusage_children_before;
	struct rusage rusage_self_after, rusage_children_after;
	struct timeval tv_self, tv_children, tv_total;
	struct timespec ts_start, ts_finish;
	long i, iteration;
	char *buf;
	ssize_t len;
	int fd, flags;
	double secs, rate;
	cpuset_t cpuset_mask;

	/*
	 * For the purposes of lab simplicity, pin the benchmark (this process
	 * and all its children processes) to CPU 0.
	 */
	CPU_ZERO(&cpuset_mask);
	CPU_SET(0, &cpuset_mask);
	if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
	    sizeof(cpuset_mask), &cpuset_mask) < 0)
		xo_err(EX_OSERR, "FAIL: cpuset_setaffinity");

	if (!qflag)
		xo_open_list("benchmark_samples");
	for (iteration = 0; iteration < iterations; iteration++) {
		/*
		 * Allocate zero-filled memory for our I/O buffer.
		 */
		buf = mmap(NULL, buffersize, PROT_READ | PROT_WRITE,
		    MAP_ANON | MAP_PRIVATE, -1, 0);
		if (buf == MAP_FAILED)
			xo_err(EX_OSERR, "FAIL: mmap");

		/*
		 * If we're in 'create' mode, then create (or truncate) the
		 * file, and don't do performance measurement.  In 'benchmark'
		 * mode, use only existing files, but allow buffer-cache
		 * bypass if requested.
		 */
		switch (operation) {
		case OPERATION_CREATE:
			flags = O_RDWR | O_CREAT | O_TRUNC;
			break;

		case OPERATION_READ:
			flags = O_RDONLY;
			break;

		case OPERATION_WRITE:
			flags = O_RDWR;
			break;
		}
		if (dflag)
			flags |= O_DIRECT;
		fd = open(path, flags, 0600);
		if (fd < 0)
			xo_err(EX_NOINPUT, "FAIL: %s", path);

		/*
		 * Before we start, fsync() the target file in case any I/O
		 * remains pending from prior work, and also sync() the
		 * filesystem so that it is fairly quiesced for our benchmark
		 * run.  Give things a second to settle down.
		 */
		if (!Bflag) {
			/* Flush terminal output. */
			fflush(stdout);
			fflush(stderr);

			/* Flush target file. */
			(void)fsync(fd);
			(void)fsync(fd);

			/* Flush filesystems as a whole. */
			(void)sync();
			(void)sync();
			(void)sync();

			/*
			 * Let things settle.
			 *
			 * NB: This will have the side effect of aliasing
			 * execution to the timer.  Unclear if this is a good
			 * thing.
			 */
			(void)sleep(1);
		}

		if (gflag) {
			if (getrusage(RUSAGE_SELF, &rusage_self_before) < 0)
				xo_err(EX_OSERR, "FAIL: getrusage(SELF)");
			if (getrusage(RUSAGE_CHILDREN,
			    &rusage_children_before) < 0)
				xo_err(EX_OSERR, "FAIL: getrusage(CHILDREN)");
		}

		/*
		 * Run the benchmark before generating any output so that the
		 * act of generating output doesn't, itself, perturb the
		 * measurement.
		 *
		 * NB: These two calls to clock_gettime() are useful
		 * bracketing system calls if you want to look at just the I/O
		 * bit of the benchmark, and not the whole program run.  Do
		 * make sure that you look only at clock_gettime() system
		 * calls from the benchmark as other threads in the system may
		 * use the call as well!
		 *
		 * NB2: Because of vdso optimisations, we now need to directly
		 * call the system call, or time queries are serviced in
		 * userspace.
		 */
		if (__sys_clock_gettime(CLOCK_REALTIME, &ts_start) < 0)
			xo_errx(EX_OSERR, "FAIL: clock_gettime");

		/*
		 * HERE BEGINS THE BENCHMARK.
		 */
		for (i = 0; i < blockcount; i++) {
			switch (operation) {
			case OPERATION_CREATE:
			case OPERATION_WRITE:
				len = write(fd, buf, buffersize);
				if (len < 0)
					xo_err(EX_IOERR, "FAIL: write");
				if (len != buffersize)
					xo_errx(EX_IOERR,
					    "FAIL: partial write");
				break;

			case OPERATION_READ:
				len = read(fd, buf, buffersize);
				if (len < 0)
					xo_err(EX_IOERR, "areda");
				if (len != buffersize)
					xo_errx(EX_IOERR,
					    "FAIL: partial read");
				break;
			}
		}
		if (sflag)
			fsync(fd);
		/*
		 * HERE ENDS THE BENCHMARK.
		 */

		if (__sys_clock_gettime(CLOCK_REALTIME, &ts_finish) < 0)
			xo_errx(EX_OSERR, "FAIL: clock_gettime");

		timespecsub(&ts_finish, &ts_start, &ts_finish);

		if (gflag) {
			if (getrusage(RUSAGE_SELF, &rusage_self_after) < 0)
				xo_err(EX_OSERR, "FAIL: getrusage(SELF)");
			if (getrusage(RUSAGE_CHILDREN,
			    &rusage_children_after) < 0)
			xo_err(EX_OSERR, "FAIL: get_rusage(CHILDREN)");
		}

		/* Seconds with fractional component. */
		secs = (float)ts_finish.tv_sec + (float)ts_finish.tv_nsec /
		    1000000000;

		/* Bytes/second. */
		rate = totalsize / secs;

		/* Kilobytes/second. */
		rate /= (1024);

		/*
		 * Now we can disruptively print things -- if we're not in
		 * quiet mode.
		 */
		if (!qflag) {
			/*
			 * Then our one datum.  In the future, we might print
			 * multiple data items.
			 */
			xo_open_instance("datum");
			xo_emit("datum:\n");
			xo_emit("  bandwidth: {:bandwidth/%1.2F} KBytes/sec\n",
			    rate);
			/* XXXRW: Ideally would print as a float? */
			xo_emit("  time: {:time/%jd.%09jd} seconds\n",
			    (intmax_t)ts_finish.tv_sec,
			    (intmax_t)ts_finish.tv_nsec);
		}
		if (!qflag && gflag) {
			/* User time. */
			timersub(&rusage_self_after.ru_utime,
			    &rusage_self_before.ru_utime, &tv_self);
			timersub(&rusage_children_after.ru_utime,
			    &rusage_children_before.ru_utime, &tv_children);
			timeradd(&tv_self, &tv_children, &tv_total);
			xo_emit("  utime: {:utime/%jd.%06jd} seconds\n",
			    tv_total.tv_sec, tv_total.tv_usec);

			/* System time. */
			timersub(&rusage_self_after.ru_stime,
			    &rusage_self_before.ru_stime, &tv_self);
			timersub(&rusage_children_after.ru_stime,
			    &rusage_children_before.ru_stime, &tv_children);
			timeradd(&tv_self, &tv_children, &tv_total);
			xo_emit("  stime: {:stime/%jd.%06jd} seconds\n",
			    tv_total.tv_sec, tv_total.tv_usec);

			/* Context switches. */
			xo_emit("  nvcsw: {:nvcsw/%ld} "
			    "voluntary context switches\n",
			    (rusage_self_after.ru_nvcsw -
			    rusage_self_before.ru_nvcsw) +
			    (rusage_children_after.ru_nvcsw -
			    rusage_children_before.ru_nvcsw));
			xo_emit("  nivcsw: {:nivcsw/%ld} "
			    "involuntary context switches\n",
			    (rusage_self_after.ru_nivcsw -
			    rusage_self_before.ru_nivcsw) +
			    (rusage_children_after.ru_nivcsw -
			    rusage_children_before.ru_nivcsw));

			/* Blocks read and written. */
			xo_emit("  inblock: {:inblock/%ld} blocks\n",
			    (rusage_self_after.ru_inblock -
			    rusage_self_before.ru_inblock) +
			    (rusage_children_after.ru_inblock -
			    rusage_children_before.ru_inblock));
			xo_emit("  oublock: {:oublock/%ld} blocks\n",
			    (rusage_self_after.ru_oublock -
			    rusage_self_before.ru_oublock) +
			    (rusage_children_after.ru_oublock -
			    rusage_children_before.ru_oublock));
		}
		if (!qflag){
			xo_close_instance("datum");
			xo_flush();
		}

		/*
		 * Just a little cleaning up between runs.
		 */
		close(fd);
		munmap(buf, buffersize);
	}
	if (!qflag) {
		xo_close_list("benchmark_samples");
		xo_finish();
	}
	close(fd);
}

/*
 * main(): parse arguments, invoke benchmark function.
 */
int
main(int argc, char *argv[])
{
	const char *path;
	char *endp;
	int ch;

	argc = xo_parse_args(argc, argv);
	if (argc < 1)
		exit(EX_USAGE);

	buffersize = BLOCKSIZE;
	iterations = ITERATIONS;
	totalsize = TOTALSIZE;
	path = NULL;
	while ((ch = getopt(argc, argv, "Bb:dgjn:qst:v")) != -1) {
		switch (ch) {
		case 'B':
			Bflag++;
			break;

		case 'b':
			buffersize = strtol(optarg, &endp, 10);
			if (*optarg == '\0' || *endp != '\0' || buffersize <= 0)
				usage();
			break;

		case 'd':
			dflag++;
			break;

		case 'g':
			gflag++;
			break;

		case 'j':
			xo_set_style(NULL, XO_STYLE_JSON);
			xo_set_flags(NULL, XOF_PRETTY);
			break;

		case 'n':
			iterations = strtol(optarg, &endp, 10);
			if (*optarg == '\0' || *endp != '\0' || iterations <= 0)
				usage();
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

	/*
	 * We expect a mode of operation and file path as the remaining two
	 * arguments.
	 */
	argc -= optind;
	argv += optind;
	if (argc != 2)
		usage();
	operation = operation_from_string(argv[0]);
	if (operation == OPERATION_INVALID)
		usage();
	path = argv[1];

	/*
	 * 'create' mode doesn't accept flags other than block/total size, so
	 * reject if we find any.  However, we then force some flags on to
	 * control behaviour in io() -- i.e., to write().
	 */
	if (operation == OPERATION_CREATE) {
		if (Bflag || dflag || sflag || (iterations != ITERATIONS))
			usage();
		Bflag = 1;	/* Don't do benchmark prep. */
	} else if (operation == OPERATION_DESCRIBE)
		vflag = 1;

	if (totalsize % buffersize != 0)
		xo_errx(EX_USAGE, "FAIL: data size (%ld) is not a multiple "
		    "of buffersize (%ld)", totalsize, buffersize);
	blockcount = totalsize / buffersize;
	if (blockcount < 0)
		xo_errx(EX_USAGE, "FAIL: negative block count");

	/*
	 * Configuration information first, if requested.  If this is
	 * OPERATION_DESCRIBE, that's all we do.
	 */
	if (!qflag && vflag)
		print_configuration(path);
	if (operation == OPERATION_CREATE || operation == OPERATION_READ ||
	    operation == OPERATION_WRITE)
		io(path);
	exit(0);
}
