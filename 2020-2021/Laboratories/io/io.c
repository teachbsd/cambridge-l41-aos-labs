/*-
 * Copyright (c) 2015, 2020 Robert N. M. Watson
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
#include <sys/time.h>

#include <fcntl.h>
#include <inttypes.h>
#include <libxo/xo.h>
#include <stdio.h>
#include <stdlib.h>
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
static unsigned int cflag;	/* create */
static unsigned int dflag;	/* O_DIRECT */
static unsigned int qflag;	/* quiet */
static unsigned int rflag;	/* read() */
static unsigned int sflag;	/* fsync() */
static unsigned int vflag;	/* verbose */
static unsigned int wflag;	/* write() */

static long buffersize;		/* I/O buffer size */
static long iterations;		/* number of iterations  to perform */
static long totalsize;		/* total I/O size; multiple of buffer size */

/*
 * Print usage message and exit.
 */
static void
usage(void)
{

	xo_error("usage: io %s -c|-r|-w [-Bdjqsv] [-b buffersize]\n"
	    "    [-n iterations] [-t totalsize] path\n", PROGNAME);
	xo_error("\n"
  "Modes (pick one):\n"
  "    -c              'create mode': create benchmark data file\n"
  "    -r              'read mode': read() benchmark\n"
  "    -w              'write mode': write() benchmark\n"
  "\n"
  "Optional flags:\n"
  "    -B              Run in bare mode: no preparatory activities\n"
  "    -d              Set O_DIRECT flag to bypass buffer cache\n"
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

/*
 * The I/O benchmark itself.  Perform any necessary setup.  Open the file or
 * device.  Take a timestamp.  Perform the work.  Take another timestamp.
 * (Optionally) print the results.  (n) times.
 */
static void
io(const char *path)
{
	struct timespec ts_start, ts_finish;
	long blockcount, i, iteration;
	char *buf;
	ssize_t len;
	int fd;
	double secs, rate;
	cpusetid_t cpuset_id;
	cpuset_t cpuset_mask;

	if (totalsize % buffersize != 0)
		xo_errx(EX_USAGE, "FAIL: data size (%ld) is not a multiple "
		    "of buffersize (%ld)", totalsize, buffersize);
	blockcount = totalsize / buffersize;
	if (blockcount < 0)
		xo_errx(EX_USAGE, "FAIL: negative block count");

	/*
	 * For the purposes of lab simplicity, pin the benchmark (this process
	 * and all its children processes) to CPU 0.
	 */
	if (cpuset(&cpuset_id) < 0)
		xo_err(EX_OSERR, "FAIL: cpuset");
	CPU_ZERO(&cpuset_mask);
	CPU_SET(1, &cpuset_mask);
	if (cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, -1,
	    sizeof(cpuset_mask), &cpuset_mask) < 0)
		xo_err(EX_OSERR, "FAIL: cpuset_setaffinity");

	/*
	 * Configuration information first, if requested.
	 */
	if (!qflag && vflag) {
		xo_open_container("benchmark_configuration");
		xo_emit("Benchmark configuration:\n");
		xo_emit("  buffersize: {:buffersize/%ld}\n", buffersize);
		xo_emit("  totalsize: {:totalsize/%ld}\n", totalsize);
		xo_emit("  blockcount: {:blockcount/%ld}\n", blockcount);
		xo_emit("  operation: {:operation/%s}\n", cflag ?  "create" :
		    (wflag ? "write" : "read"));
		xo_emit("  path: {:path/%s}\n", path);
		xo_close_container("benchmark_configuration");
		xo_flush();
	}

	if (!qflag)
		xo_open_list("benchmark_samples");
	for (iteration = 0; iteration < iterations; iteration++) {
		/*
		 * Allocate zero-filled memory for our I/O buffer.
		 */
		buf = mmap(NULL, buffersize, PROT_READ | PROT_WRITE, MAP_ANON,
		    -1, 0);
		if (buf == NULL)
			xo_err(EX_OSERR, "FAIL: mmap");

		/*
		 * If we're in 'create' mode, then create (or truncate) the
		 * file, and don't do performance measurement.  In 'benchmark'
		 * mode, use only existing files, but allow buffer-cache
		 * bypass if requested.
		 */
		if (cflag)
			fd = open(path, O_RDWR | O_CREAT | O_TRUNC, 0600);
		else 
			fd = open(path, (wflag ? O_RDWR : O_RDONLY) |
			    (dflag ? O_DIRECT : 0));
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
		 */
		if (clock_gettime(CLOCK_REALTIME, &ts_start) < 0)
			xo_errx(EX_OSERR, "FAIL: clock_gettime");

		/*
		 * HERE BEGINS THE BENCHMARK.
		 */
		for (i = 0; i < blockcount; i++) {
			if (wflag)
				len = write(fd, buf, buffersize);
			else
				len = read(fd, buf, buffersize);
			if (len < 0)
				xo_err(EX_IOERR, "FAIL: %s", wflag ? "write" :
				    "read");
			if (len != buffersize)
				xo_errx(EX_IOERR, "FAIL: partial %s", wflag ?
				    "write" : "read");
		}
		if (sflag)
			fsync(fd);
		/*
		 * HERE ENDS THE BENCHMARK.
		 */

		if (clock_gettime(CLOCK_REALTIME, &ts_finish) < 0)
			xo_errx(EX_OSERR, "FAIL: clock_gettime");

		timespecsub(&ts_finish, &ts_start, &ts_finish);
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
	if (argc < 0)
		exit(EX_USAGE);

	buffersize = BLOCKSIZE;
	iterations = ITERATIONS;
	totalsize = TOTALSIZE;
	path = NULL;
	while ((ch = getopt(argc, argv, "Bb:cdjn:qrst:vw")) != -1) {
		switch (ch) {
		case 'B':
			Bflag++;
			break;

		case 'b':
			buffersize = strtol(optarg, &endp, 10);
			if (*optarg == '\0' || *endp != '\0' || buffersize <= 0)
				usage();
			break;

		case 'c':
			cflag++;
			break;

		case 'd':
			dflag++;
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

		case 'r':
			rflag++;
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

		case 'w':
			wflag++;
			break;

		case '?':
		default:
			usage();
		}
	}

	/*
	 * Exactly one of 'read mode', 'write mode', or 'create mode'.
	 */
	if (cflag + rflag + wflag != 1)
		usage();

	/*
	 * 'create' mode doesn't accept flags other than block/total size, so
	 * reject if we find any.  However, we then force some flags on to
	 * control behaviour in io() -- i.e., to write().
	 */
	if (cflag && (Bflag || dflag || qflag || rflag || sflag || vflag))
		usage();
	if (cflag) {
		Bflag = 1;	/* Don't do benchmark prep. */
		vflag = 1;	/* Provide status information. */
		wflag = 1;	/* Do use write(). */
	}
	argc -= optind;
	argv += optind;
	if (argc == 0 || argc > 1)
		usage();
	path = argv[0];
	io(path);
	exit(0);
}
