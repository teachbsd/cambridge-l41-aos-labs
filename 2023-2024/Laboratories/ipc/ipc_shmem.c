/*-
 * Copyright (c) 2023 Robert N. M. Watson
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
#include <sys/mman.h>

#include <errno.h>
#include <inttypes.h>
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

/*
 * Simplistic shared memory buffer implementation.  A memory map is shared by
 * the two parties (threads or processes), with a buffer of size 'buffersize'.
 * A mutex and two condition variables ping and ping ownership back and forth
 * between the two threads/processes.  All data copying is performed in
 * userspace rather than in the kernel.
 */

#define	min(x, y)	((x) < (y) ? (x) : (y))
#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))

struct shmem_metadata {
	pthread_mutex_t	sm_mutex;		/* Synchronise buffer+flag. */
	pthread_cond_t	sm_cond_empty;		/* Signal now empty. */
	pthread_cond_t	sm_cond_full;		/* Signal now full. */
	int		sm_datapresent;		/* Unread data is present. */
} * volatile shmem_metadata_ptr;		/* Shared metadata .*/
static uint8_t * volatile shmem_buffer_ptr;	/* Shared buffer. */

void
sender_shmem(struct sender_argument *sap)
{
	long write_sofar;

	/* Modeled on the fd logic, but without partial writes. */
	write_sofar = 0;
	if (pthread_mutex_lock(&shmem_metadata_ptr->sm_mutex) < 0)
		xo_err(EX_OSERR, "pthread_mutex_lock");
	while (write_sofar < totalsize) {
		while (shmem_metadata_ptr->sm_datapresent == 1) {
			if (pthread_cond_wait(
			    &shmem_metadata_ptr->sm_cond_empty,
			    &shmem_metadata_ptr->sm_mutex) < 0)
				xo_err(EX_OSERR, "pthread_cond_wait");
		}
		const size_t bytes_to_write = min(buffersize, totalsize -
		    write_sofar);
		memcpy(shmem_buffer_ptr, sap->sa_buffer, bytes_to_write);
		write_sofar += bytes_to_write;
		shmem_metadata_ptr->sm_datapresent = 1;
		if (pthread_cond_signal(&shmem_metadata_ptr->sm_cond_full)
		    < 0)
			xo_err(EX_OSERR, "pthread_cond_signal");
	}
	if (pthread_mutex_unlock(&shmem_metadata_ptr->sm_mutex) < 0)
		xo_err(EX_OSERR, "pthread_mutex_unlock");
}

void
receiver_shmem(intptr_t readfd, void *buf)
{
	long read_sofar;

	/* Modeled on the fd logic, but without partial reads. */
	read_sofar = 0;
	if (pthread_mutex_lock(&shmem_metadata_ptr->sm_mutex) < 0)
		xo_err(EX_OSERR, "pthread_mutex_lock");
	while (read_sofar < totalsize) {
		while (shmem_metadata_ptr->sm_datapresent == 0) {
			if (pthread_cond_wait(
			    &shmem_metadata_ptr->sm_cond_full,
			    &shmem_metadata_ptr->sm_mutex) < 0)
				xo_err(EX_OSERR, "pthread_cond_wait");
		}
		const size_t bytes_to_read = min(buffersize, totalsize -
		    read_sofar);
		memcpy(buf, shmem_buffer_ptr, bytes_to_read);
		read_sofar += bytes_to_read;
		shmem_metadata_ptr->sm_datapresent = 0;
		if (pthread_cond_signal(&shmem_metadata_ptr->sm_cond_empty)
		    < 0)
			xo_err(EX_OSERR, "pthread_cond_signal");
	}
	if (pthread_mutex_unlock(&shmem_metadata_ptr->sm_mutex) < 0)
		xo_err(EX_OSERR, "pthread_mutex_unlock");
}

/*
 * Allocate, configure, as needed connect, and return a pair of IPC object
 * handle via *readfdp and *writefdp.
 */
void
ipc_objects_allocate_shmem(intptr_t *readfdp, intptr_t *writefdp)
{
	pthread_mutexattr_t mattr;
	pthread_condattr_t cattr;

	/*
	 * Set up a single, shared, inherited page for metadata.  Pre-zero
	 * to prevent faults during the benchmark.
	 */
	shmem_metadata_ptr = mmap(NULL, getpagesize(), PROT_READ|PROT_WRITE,
	    MAP_ANON, -1, 0);
	if (shmem_metadata_ptr == MAP_FAILED)
		xo_err(EX_OSERR, "mmap");
	memset(shmem_metadata_ptr, 0, getpagesize());
	if (minherit(shmem_metadata_ptr, getpagesize(), INHERIT_SHARE) < 0)
		xo_err(EX_OSERR, "minherit");

	/*
	 * Set up the buffer itself, rounded up to page size, in the same way.
	 */
	shmem_buffer_ptr = mmap(NULL, roundup(buffersize, getpagesize()),
	    PROT_READ|PROT_WRITE, MAP_ANON, -1, 0);
	if (shmem_buffer_ptr == MAP_FAILED)
		xo_err(EX_OSERR, "mmap");
	memset(shmem_buffer_ptr, 0, roundup(buffersize, getpagesize()));
	if (minherit(shmem_buffer_ptr, getpagesize(), INHERIT_SHARE) < 0)
		xo_err(EX_OSERR, "minherit");

	/*
	 * Intialise mutex and condition variables as 'shared' only if we will
	 * use them from more than one process.
	 */
	if (pthread_mutexattr_init(&mattr) < 0)
		xo_err(EX_OSERR, "pthread_mutexattr_init");
	if (benchmark_mode == BENCHMARK_MODE_2PROC) {
		if (pthread_mutexattr_setpshared(&mattr,
		    PTHREAD_PROCESS_SHARED) < 0)
			xo_err(EX_OSERR, "pthread_mutexattr_setpshared");
	}
	if (pthread_mutex_init(&shmem_metadata_ptr->sm_mutex, &mattr) < 0)
		xo_err(EX_OSERR, "pthread_mutex_init");
	if (pthread_condattr_init(&cattr) < 0)
		xo_err(EX_OSERR, "pthread_condattr_int");
	if (benchmark_mode == BENCHMARK_MODE_2PROC) {
		if (pthread_condattr_setpshared(&cattr,
		    PTHREAD_PROCESS_SHARED) < 0)
			xo_err(EX_OSERR, "pthread_condattr_setpshared");
	}
	if (pthread_cond_init(&shmem_metadata_ptr->sm_cond_empty, &cattr) < 0)
		xo_err(EX_OSERR, "pthread_cond_init");
	if (pthread_cond_init(&shmem_metadata_ptr->sm_cond_full, &cattr) < 0)
		xo_err(EX_OSERR, "pthread_cond_init");

	/*
	 * Initially empty.
	 */
	shmem_metadata_ptr->sm_datapresent = 0;
}

void
ipc_objects_free_shmem(intptr_t read_handlep, intptr_t write_handlep)
{

	if (munmap(shmem_metadata_ptr, getpagesize()) < 0)
		xo_err(EX_OSERR, "munmap");
	shmem_metadata_ptr = NULL;
	if (munmap(shmem_buffer_ptr, roundup(buffersize, getpagesize())) < 0)
		xo_err(EX_OSERR, "munmap");
	shmem_buffer_ptr = NULL;
}
