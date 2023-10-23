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
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
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

int	__sys_clock_gettime(__clockid_t, struct timespec *ts);

static void	ipc_objects_free(intptr_t read_handle, intptr_t write_handle);

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

/*
 * Sender routine, agnostic to IPC type.
 */
static void
sender(struct sender_argument *sap)
{

	if (__sys_clock_gettime(CLOCK_REALTIME, &sap->sa_starttime) < 0)
		xo_err(EX_OSERR, "FAIL: __sys_clock_gettime");
	if (benchmark_pmc != BENCHMARK_PMC_NONE)
		pmc_begin();

	/*
	 * HERE BEGINS THE BENCHMARK.
	 */
	switch (ipc_type) {
	case BENCHMARK_IPC_PIPE:
	case BENCHMARK_IPC_LOCAL_SOCKET:
	case BENCHMARK_IPC_TCP_SOCKET:
		sender_fd(sap);
		break;

	case BENCHMARK_IPC_SHMEM:
		sender_shmem(sap);
		break;

	default:
		assert(0);
	}
}

/*
 * Receiver routine, agnostic to IPC type.
 */
static struct timespec
receiver(intptr_t read_handle, void *buf)
{
	struct timespec finishtime;

	switch (ipc_type) {
	case BENCHMARK_IPC_PIPE:
	case BENCHMARK_IPC_LOCAL_SOCKET:
	case BENCHMARK_IPC_TCP_SOCKET:
		receiver_fd(read_handle, buf);
		break;

	case BENCHMARK_IPC_SHMEM:
		receiver_shmem(read_handle, buf);
		break;

	default:
		assert(0);
	}

	/*
	 * HERE ENDS THE BENCHMARK.
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
do_2thread(intptr_t read_handle, intptr_t write_handle, long msgcount,
    void *readbuf, void *writebuf)
{
	struct timespec finishtime;
	pthread_t thread;

	/*
	 * We can just use ordinary shared memory between the two threads --
	 * no need to do anything special.
	 */
	sa.sa_write_handle = write_handle;
	sa.sa_msgcount = msgcount;
	sa.sa_buffer = writebuf;
	if (pthread_create(&thread, NULL, second_thread, &sa) < 0)
		xo_err(EX_OSERR, "FAIL: pthread_create");
	finishtime = receiver(read_handle, readbuf);
	if (pthread_join(thread, NULL) < 0)
		xo_err(EX_OSERR, "FAIL: pthread_join");
	timespecsub(&finishtime, &sa.sa_starttime, &finishtime);
	return (finishtime);
}

static struct timespec
do_2proc(intptr_t read_handle, intptr_t write_handle, long msgcount,
    void *readbuf, void *writebuf)
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
	sap->sa_write_handle = write_handle;
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
	finishtime = receiver(read_handle, readbuf);
	if ((pid2 = waitpid(pid, NULL, 0)) < 0)
		xo_err(EX_OSERR, "FAIL: waitpid");
	if (pid2 != pid)
		xo_err(EX_OSERR, "FAIL: waitpid PID mismatch");
	timespecsub(&finishtime, &sap->sa_starttime, &finishtime);
	return (finishtime);
}

/*
 * Allocate, configure, as needed connect, and return a pair of IPC object
 * handle via *read_handlep and *write_handlep.
 */
static void
ipc_objects_allocate(intptr_t *read_handlep, intptr_t *write_handlep)
{

	switch (ipc_type) {
	case BENCHMARK_IPC_PIPE:
	case BENCHMARK_IPC_LOCAL_SOCKET:
	case BENCHMARK_IPC_TCP_SOCKET:
		ipc_objects_allocate_fd(read_handlep, write_handlep);
		break;

	case BENCHMARK_IPC_SHMEM:
		ipc_objects_allocate_shmem(read_handlep, write_handlep);
		break;

	default:
		assert(0);
	}
}

static void
ipc_objects_free(intptr_t read_handle, intptr_t write_handle)
{

	switch (ipc_type) {
	case BENCHMARK_IPC_PIPE:
	case BENCHMARK_IPC_LOCAL_SOCKET:
	case BENCHMARK_IPC_TCP_SOCKET:
		ipc_objects_free_fd(read_handle, write_handle);
		break;

	case BENCHMARK_IPC_SHMEM:
		ipc_objects_free_shmem(read_handle, write_handle);
		break;

	default:
		assert(0);
	}
}

void
ipc(void)
{
	struct rusage rusage_self_before, rusage_children_before;
	struct rusage rusage_self_after, rusage_children_after;
	struct timeval tv_self, tv_children, tv_total;
	struct timespec ts;
	void *readbuf, *writebuf;
	int iteration;
	intptr_t read_handle, write_handle;
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
		ipc_objects_allocate(&read_handle, &write_handle);

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
		case BENCHMARK_MODE_2THREAD:
			ts = do_2thread(read_handle, write_handle, msgcount,
			    readbuf, writebuf);
			break;

		case BENCHMARK_MODE_2PROC:
			ts = do_2proc(read_handle, write_handle, msgcount,
			    readbuf, writebuf);
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
		ipc_objects_free(read_handle, write_handle);
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
