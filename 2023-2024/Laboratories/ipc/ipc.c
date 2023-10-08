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
#include <sys/cpuset.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/select.h>
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
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include "ipc.h"
#include "main.h"
#include "pmc.h"

#define	max(x, y)	((x) > (y) ? (x) : (y))
#define	min(x, y)	((x) < (y) ? (x) : (y))

int	__sys_clock_gettime(__clockid_t, struct timespec *ts);

/*
 * The I/O benchmark itself.  Perform any necessary setup.  Open the file or
 * device.  Take a timestamp.  Perform the work.  Take another timestamp.
 * (Optionally) print the results.
 */

/*
 * Whether using threads or processes, we have the second thread/process do
 * the sending, and the first do the receiving, so that it reliably knows when
 * the benchmark is done.  The sender will write the timestamp to shared
 * memory before sending any bytes, so the receipt of any byte means that the
 * timestamp has been stored.
 *
 * XXXRW: If we run this benchmark on multicore, we may want to put in a
 * memory barrier of some sort on either side, although because a system call
 * is involved, it is probably not necessary.  I wonder what C and POSIX have
 * to say about that.
 */
struct sender_argument {
	struct timespec	 sa_starttime;	/* Sender stores start time here. */
	int		 sa_writefd;	/* Caller provides send fd here. */
	long		 sa_msgcount;	/* Caller provides msg count here. */
	void		*sa_buffer;	/* Caller provides buffer here. */
};

static void
sender(struct sender_argument *sap)
{
	ssize_t len;
	long write_sofar;

	if (__sys_clock_gettime(CLOCK_REALTIME, &sap->sa_starttime) < 0)
		xo_err(EX_OSERR, "FAIL: __sys_clock_gettime");
	if (benchmark_pmc != BENCHMARK_PMC_NONE)
		pmc_begin();

	/*
	 * HERE BEGINS THE BENCHMARK (2-thread/2-proc).
	 */
	write_sofar = 0;
	while (write_sofar < totalsize) {
		const size_t bytes_to_write = min(buffersize, totalsize - write_sofar);
		len = write(sap->sa_writefd, sap->sa_buffer,
		    min(buffersize, totalsize - write_sofar));
		/*printf("write(%d, %zd, %zd) = %zd\n", sap->sa_writefd, 0, bytes_to_write, len);*/
		if (len != bytes_to_write) {
			xo_errx(EX_IOERR, "blocking write() returned early: "
			    "%zd != %zd", len, bytes_to_write);
		}
		if (len < 0)
			xo_err(EX_IOERR, "FAIL: write");
		write_sofar += len;
	}
}

static struct timespec
receiver(int readfd, void *buf)
{
	struct timespec finishtime;
	ssize_t len;
	long read_sofar;

	read_sofar = 0;
	/** read() always returns as soon as there is something to read,
	 * i.e. one pipe/socket buffer size. Make sure we use the whole buffer */
	while (read_sofar < totalsize) {
		const size_t offset = read_sofar % buffersize;
		const size_t bytes_to_read = min(totalsize - read_sofar, buffersize - offset);
		len = read(readfd, buf + offset, bytes_to_read);
		/*printf("read(%d, %zd, %zd) = %zd\n", readfd, offset, bytes_to_read, len);*/
		/* if (len != bytes_to_read) {
			warn("blocking read returned early: %zd != %zd", len, bytes_to_read);
		} */
		if (len < 0)
			xo_err(EX_IOERR, "FAIL: read");
		read_sofar += len;
	}

	/*
	 * HERE ENDS THE BENCHMARK (2-thread/2-proc).
	 */
	if (benchmark_pmc != BENCHMARK_PMC_NONE)
		pmc_end();
	if (__sys_clock_gettime(CLOCK_REALTIME, &finishtime) < 0)
		xo_err(EX_OSERR, "FAIL: __sys_clock_gettime");
	return (finishtime);
}

static void *
second_thread(void *arg)
{
	struct sender_argument *sap = arg;

	if (!Bflag)
		sleep(1);
	sender(sap);

	/*
	 * No action needed to terminate thread other than to return.
	 */
	return (NULL);
}

static struct sender_argument sa;

static struct timespec
do_2thread(int readfd, int writefd, long msgcount, void *readbuf,
    void *writebuf)
{
	struct timespec finishtime;
	pthread_t thread;

	/*
	 * We can just use ordinary shared memory between the two threads --
	 * no need to do anything special.
	 */
	sa.sa_writefd = writefd;
	sa.sa_msgcount = msgcount;
	sa.sa_buffer = writebuf;
	if (pthread_create(&thread, NULL, second_thread, &sa) < 0)
		xo_err(EX_OSERR, "FAIL: pthread_create");
	finishtime = receiver(readfd, readbuf);
	if (pthread_join(thread, NULL) < 0)
		xo_err(EX_OSERR, "FAIL: pthread_join");
	timespecsub(&finishtime, &sa.sa_starttime, &finishtime);
	return (finishtime);
}

static struct timespec
do_2proc(int readfd, int writefd, long msgcount, void *readbuf,
    void *writebuf)
{
	struct sender_argument *sap;
	struct timespec finishtime;
	pid_t pid, pid2;

	/*
	 * Set up a shared page across fork() that will allow not just
	 * passing arguments, but also getting back the starting timestamp
 	 * that may be somewhat after the time of fork() in this process.
	 */
	if ((sap = mmap(NULL, getpagesize(), PROT_READ | PROT_WRITE, MAP_ANON,
	    -1, 0)) == MAP_FAILED)
		xo_err(EX_OSERR, "mmap");
	if (minherit(sap, getpagesize(), INHERIT_SHARE) < 0)
		xo_err(EX_OSERR, "minherit");
	sap->sa_writefd = writefd;
	sap->sa_msgcount = msgcount;
	sap->sa_buffer = writebuf;
	pid = fork();
	if (pid == 0) {
		if (!Bflag)
			sleep(1);
		sender(sap);
		if (!Bflag)
			sleep(1);
		_exit(0);
	}
	finishtime = receiver(readfd, readbuf);
	if ((pid2 = waitpid(pid, NULL, 0)) < 0)
		xo_err(EX_OSERR, "FAIL: waitpid");
	if (pid2 != pid)
		xo_err(EX_OSERR, "FAIL: waitpid PID mismatch");
	timespecsub(&finishtime, &sap->sa_starttime, &finishtime);
	return (finishtime);
}

/*
 * The single threading case is quite different from the two-thread/process
 * case, as we need to manually interleave the sender and recipient.  Note the
 * opportunity for deadlock if the buffer size is greater than what the IPC
 * primitive provides.
 *
 * The buffer pointer must point at a buffer of size 'buffersize' here.
 *
 * XXXRW: Should we be explicitly setting the buffer size for the file
 * descriptor?  Pipes appear not to offer a way to do this.
 */
static struct timespec
do_1thread(int readfd, int writefd, long msgcount, void *readbuf,
    void *writebuf)
{
	struct timespec starttime, finishtime;
	fd_set fdset_read, fdset_write;
	long read_sofar, write_sofar;
	ssize_t len_read, len_write;
	int flags;

	flags = fcntl(readfd, F_GETFL, 0);
	if (flags < 0)
		xo_err(EX_OSERR, "FAIL: fcntl(readfd, F_GETFL, 0)");
	if (fcntl(readfd, F_SETFL, flags | O_NONBLOCK) < 0)
		xo_err(EX_OSERR, "FAIL: fcntl(readfd, F_SETFL, "
		    "flags | O_NONBLOCK)");
	flags = fcntl(writefd, F_GETFL, 0);
	if (flags < 0)
		xo_err(EX_OSERR, "FAIL: fcntl(writefd, F_GETFL, 0)");
	if (fcntl(writefd, F_SETFL, flags | O_NONBLOCK) < 0)
		xo_err(EX_OSERR, "FAIL: fcntl(writefd, F_SETFL, "
		    "flags | O_NONBLOCK)");

	FD_ZERO(&fdset_read);
	FD_SET(readfd, &fdset_read);
	FD_ZERO(&fdset_write);
	FD_SET(writefd, &fdset_write);

	if (__sys_clock_gettime(CLOCK_REALTIME, &starttime) < 0)
		xo_err(EX_OSERR, "FAIL: __sys_clock_gettime");
	if (benchmark_pmc != BENCHMARK_PMC_NONE)
		pmc_begin();

	/*
	 * HERE BEGINS THE BENCHMARK (1-thread).
	 */
	read_sofar = write_sofar = 0;
	/** As the I/O is nonblocking write()/read() will return after only
	 * reading part of the buffer. For this benchmark we ensure that
	 * the whole buffer is used instead of always using offset 0 to
	 * have the same behaviour as the 2thread/2proc version */
	while (read_sofar < totalsize) {
		const size_t remaining_write = totalsize - write_sofar;
		if (remaining_write > 0) {
			const size_t offset = write_sofar % buffersize;
			const size_t bytes_to_write = min(remaining_write, buffersize - offset);
			len_write = write(writefd, writebuf + offset, bytes_to_write);
			/*printf("write(%d, %zd, %zd) = %zd\n", writefd, offset, bytes_to_write, len_write);*/
			if (len_write < 0 && errno != EAGAIN)
				xo_err(EX_IOERR, "FAIL: write");
			if (len_write > 0)
				write_sofar += len_write;
		}
		if (write_sofar != 0) {
			const size_t offset = read_sofar % buffersize;
			const size_t bytes_to_read = min(totalsize - read_sofar, buffersize - offset);
			len_read = read(readfd, readbuf + offset, bytes_to_read);
			/*printf("read(%d, %zd, %zd) = %zd\n", readfd, offset, bytes_to_read, len_read);*/
			if (len_read < 0 && errno != EAGAIN)
				xo_err(EX_IOERR, "FAIL: read");
			if (len_read > 0)
				read_sofar += len_read;
		}

		/*
		 * If we've had neither read nor write progress in this
		 * iteration, block until one of reading or writing is
		 * possible.
		 */
		if (read_sofar < totalsize &&
		    (len_read == 0 && len_write == 0)) {
			if (select(max(readfd, writefd), &fdset_read,
			    &fdset_write, NULL, NULL) < 0)
				xo_err(EX_IOERR, "FAIL: select");
		}
	}

	/*
	 * HERE ENDS THE BENCHMARK (1-thread).
	 */
	if (benchmark_pmc != BENCHMARK_PMC_NONE)
		pmc_end();
	if (__sys_clock_gettime(CLOCK_REALTIME, &finishtime) < 0)
		xo_err(EX_OSERR, "FAIL: __sys_clock_gettime");
	timespecsub(&finishtime, &starttime, &finishtime);
	return (finishtime);
}

/*
 * Allocate, configure, as needed connect, and return a pair of IPC object
 * handle via *readfdp and *writefdp.
 */
static void
ipc_objects_allocate(int *readfdp, int *writefdp)
{
	struct sockaddr_in sin;
	int fd[2], listenfd, readfd, writefd, sockoptval;
	int error, flags, i, integer;

	/*
	 * Allocate a suitable IPC object.
	 */
	switch (ipc_type) {
	case BENCHMARK_IPC_PIPE:
		if (pipe(fd) < 0)
			xo_err(EX_OSERR, "FAIL: pipe");

		/*
		 * On FreeBSD, it doesn't matter which end of the pipe
		 * we use, but on other operating systems, it is
		 * sometimes the case that the first file descriptor
		 * must be used for reading, and the second for
		 * writing.
		 */
		readfd = fd[0];
		writefd = fd[1];
		break;

	case BENCHMARK_IPC_LOCAL_SOCKET:
		if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fd) < 0)
			xo_err(EX_OSERR, "FAIL: socketpair");

		/*
		 * With socket pairs, it makes no difference which one
		 * we use for reading or writing.
		 */
		readfd = fd[0];
			writefd = fd[1];
		break;

	case BENCHMARK_IPC_TCP_SOCKET:
		/*
		 * Flush the TCP host cache before starting the benchmark,
		 * to prevent retained RTT/bandwidth estimates from
		 * influencing performance results.
		 */
		integer = 1;
		if (sysctlbyname("net.inet.tcp.hostcache.purgenow", NULL,
		    NULL, &integer, sizeof(integer)) < 0)
			xo_err(EX_OSERR,
			    "sysctlbyname: net.inet.tcp.hostcache.purgenow");

		/*
		 * Listen socket and a corresponding socket address used for
		 * both binding and connecting.
		 */
		listenfd = socket(PF_INET, SOCK_STREAM, 0);
		if (listenfd < 0)
			xo_err(EX_OSERR, "FAIL: socket (listen)");
		i = 1;
		if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &i,
		    sizeof(i)) < 0)
			xo_err(EX_OSERR, "FAIL: setsockopt SO_REUSEADDR");
		bzero(&sin, sizeof(sin));
		sin.sin_len = sizeof(sin);
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		sin.sin_port = htons(tcp_port);
		if (bind(listenfd, (struct sockaddr *)&sin, sizeof(sin)) < 0)
			xo_err(EX_OSERR, "FAIL: bind");
		if (listen(listenfd, -1) < 0)
			xo_err(EX_OSERR, "FAIL: listen");

		/*
		 * Create the 'read' endpoint and connect it to the listen
		 * socket in a non-blocking manner (as we need to accept()
		 * it before the connection can complete, and don't want to
		 * deadlock).
		 *
		 * Note that it *does* matter which we use for reading vs.
		 * writing -- we intentionally wait until the full three-way
		 * handshake is done before transmitting data, and only the
		 * accepted socket has this property (i.e., waiting for the
		 * ACK in the SYN-SYN/ACK-ACK exchange).
		 */
		readfd = socket(PF_INET, SOCK_STREAM, 0);
		if (readfd < 0)
			xo_err(EX_OSERR, "FAIL: socket (read)");
		flags = fcntl(readfd, F_GETFL, 0);
		if (flags < 0)
			xo_err(EX_OSERR, "FAIL: fcntl(readfd, F_GETFL, 0)");
		if (fcntl(readfd, F_SETFL, flags | O_NONBLOCK) < 0)
			xo_err(EX_OSERR, "FAIL: fcntl(readfd, F_SETFL, "
			    "flags | O_NONBLOCK)");
		error = connect(readfd, (struct sockaddr *)&sin,
		    sizeof(sin));
		if (error < 0 && errno != EINPROGRESS)
			xo_err(EX_OSERR, "FAIL: connect");

		/*
		 * On the listen socket, now accept the 'write' endpoint --
		 * which should block until the full three-way handshake is
		 * complete.
		 */
		writefd = accept(listenfd, NULL, NULL);
		if (writefd < 0)
			xo_err(EX_OSERR, "accept");

		/*
		 * Restore blocking status to the 'read' endpoint, and close
		 * the now-unnecessary listen socket.  Any further use of
		 * the 'read' endpoint will block until the socket is ready,
		 * although in practice that is unlikely.
		 */
		if (fcntl(readfd, F_SETFL, flags) < 0)
			xo_err(EX_OSERR, "FAIL: fcntl(readfd, F_SETFL, "
			    "flags");
		close(listenfd);
		break;

	default:
		assert(0);
	}


	if (ipc_type == BENCHMARK_IPC_LOCAL_SOCKET ||
	    ipc_type == BENCHMARK_IPC_TCP_SOCKET) {
		if (sflag) {
			/*
			 * Default socket-buffer sizes may be too low (e.g.,
			 * 8K) to allow atomic sends/receives of our requested
			 * buffer length.  Extend both socket buffers to fit
			 * better.
			 */
			sockoptval = buffersize;
			if (setsockopt(writefd, SOL_SOCKET, SO_SNDBUF,
			    &sockoptval, sizeof(sockoptval)) < 0)
				xo_err(EX_OSERR, "FAIL: setsockopt "
				    "SO_SNDBUF");
			if (setsockopt(readfd, SOL_SOCKET, SO_RCVBUF,
			    &sockoptval, sizeof(sockoptval)) < 0)
				xo_err(EX_OSERR, "FAIL: setsockopt "
				    "SO_RCVBUF");
		}
	}
	*readfdp = readfd;
	*writefdp = writefd;
}

void
ipc(void)
{
	struct rusage rusage_self_before, rusage_children_before;
	struct rusage rusage_self_after, rusage_children_after;
	struct timeval tv_self, tv_children, tv_total;
	struct timespec ts;
	void *readbuf, *writebuf;
	int iteration, readfd, writefd;
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

	/*
	 * Set up the PMC library -- things done only once.
	 */
	if ((benchmark_pmc != BENCHMARK_PMC_NONE) && (pmc_init() < 0))
		xo_err(EX_OSERR, "FAIL: pmc_init");

	/*
	 * Allocate zero-filled memory for our IPC buffer.  Explicitly fill so
	 * as to take page zeroing traps now rather than during the benchmark
	 * loop itself.
	 */
	readbuf = mmap(NULL, buffersize, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0);
	if (readbuf == NULL)
		xo_err(EX_OSERR, "FAIL: mmap");
	memset(readbuf, 0, buffersize);
	writebuf = mmap(NULL, buffersize, PROT_READ | PROT_WRITE,
	    MAP_ANON, -1, 0);
	if (writebuf == NULL)
		xo_err(EX_OSERR, "FAIL: mmap");
	memset(writebuf, 0, buffersize);

	/*
	 * Start running benchmark loop.
	 */
	if (!qflag)
		xo_open_list("benchmark_samples");
	for (iteration = 0; iteration < iterations; iteration++) {
		/*
		 * Allocate and initialise performance counters, if required.
		 * Things done once per iteration.
		 */
		if (benchmark_pmc != BENCHMARK_PMC_NONE)
			pmc_setup_run();

		/*
		 * Allocate and connect a suitable IPC object handle pair.
		 */
		ipc_objects_allocate(&readfd, &writefd);

		/*
		 * Before we start, sync() the filesystem so that it is fairly
		 * quiesced from prior work.  Give things a second to settle
		 * down.
		 */
		if (!Bflag) {
			/* Flush terminal output. */
			fflush(stdout);
			fflush(stderr);

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
		 * Perform the actual benchmark; timing is done within
		 * different versions as they behave quite differently.  Each
		 * returns the total execution time from just before first
		 * byte sent to just after last byte received.  All must clean
		 * up pretty carefully so as to minimise the impact on future
		 * benchmark runs.
		 */
		switch (benchmark_mode) {
		case BENCHMARK_MODE_1THREAD:
			ts = do_1thread(readfd, writefd, msgcount, readbuf,
			    writebuf);
			break;

		case BENCHMARK_MODE_2THREAD:
			ts = do_2thread(readfd, writefd, msgcount, readbuf,
			    writebuf);
			break;

		case BENCHMARK_MODE_2PROC:
			ts = do_2proc(readfd, writefd, msgcount, readbuf,
			    writebuf);
			break;

		default:
			assert(0);
		}

		if (gflag) {
			if (getrusage(RUSAGE_SELF, &rusage_self_after) < 0)
				xo_err(EX_OSERR, "FAIL: getrusage(SELF)");
			if (getrusage(RUSAGE_CHILDREN,
			    &rusage_children_after) < 0)
				xo_err(EX_OSERR, "FAIL: get_rusage(CHILDREN)");
		}

		/* Seconds with fractional component. */
		secs = (float)ts.tv_sec + (float)ts.tv_nsec / 1000000000;

		/* Bytes/second. */
		rate = totalsize / secs;

		/* Kilobytes/second. */
		rate /= (1024);

		/*
		 * Now we can disruptively print things -- if we're not in
		 * quiet mode.
		 */
		if (!qflag) {
			xo_open_instance("datum");
			xo_emit("datum:\n");
			xo_emit("  bandwidth: {:bandwidth/%1.2F} KBytes/sec\n",
			    rate);
			/* XXXRW: Ideally would print as a float? */
			xo_emit("  time: {:time/%jd.%09jd} seconds\n",
			    (intmax_t)ts.tv_sec, (intmax_t)ts.tv_nsec);
		}
		if (!qflag && gflag) {
			/* System time. */
			timersub(&rusage_self_after.ru_stime,
			    &rusage_self_before.ru_stime, &tv_self);
			timersub(&rusage_children_after.ru_stime,
			    &rusage_children_before.ru_stime, &tv_children);
			timeradd(&tv_self, &tv_children, &tv_total);
			xo_emit("  stime: {:stime/%jd.%06jd} seconds\n",
			    tv_total.tv_sec, tv_total.tv_usec);

			/* User time. */
			timersub(&rusage_self_after.ru_utime,
			    &rusage_self_before.ru_utime, &tv_self);
			timersub(&rusage_children_after.ru_utime,
			    &rusage_children_before.ru_utime, &tv_children);
			timeradd(&tv_self, &tv_children, &tv_total);
			xo_emit("  utime: {:utime/%jd.%06jd} seconds\n",
			    tv_total.tv_sec, tv_total.tv_usec);

			/* Messages sent and received .*/
			xo_emit("  msgsnd: {:msgsnd/%ld} messages\n",
			    (rusage_self_after.ru_msgsnd -
			    rusage_self_before.ru_msgsnd) +
			    (rusage_children_after.ru_msgsnd -
			    rusage_children_before.ru_msgsnd));
			xo_emit("  msgrcv: {:msgrcv/%ld} messages\n",
			    (rusage_self_after.ru_msgrcv -
			    rusage_self_before.ru_msgrcv) +
			    (rusage_children_after.ru_msgrcv -
			    rusage_children_before.ru_msgrcv));

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
		}
		if (!qflag)
			pmc_print();
		if (!qflag) {
			xo_close_instance("datum");
			xo_flush();
		}

		/*
		 * Just a little cleaning up between runs.
		 */
		if (benchmark_pmc != BENCHMARK_PMC_NONE)
			pmc_teardown_run();
		close(readfd);
		close(writefd);
	}
	if (!qflag) {
		xo_close_list("benchmark_samples");
		xo_finish();
	}
	if (munmap(readbuf, buffersize) < 0)
		xo_err(EX_OSERR, "FAIL: munmap");
	if (munmap(writebuf, buffersize) < 0)
		xo_err(EX_OSERR, "FAIL: munmap");
}
