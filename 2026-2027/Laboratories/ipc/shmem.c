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

/*
 * Simplistic shared memory buffer implementation.
 */

#include "main.h"

#define	roundup(x, y)	((((x)+((y)-1))/(y))*(y))

struct shmem_metadata {
	u_int	sm_head;
	u_int	sm_tail;
} * volatile shmem_metadata_ptr;		/* Shared metadata .*/

static uint8_t * volatile shmem_buffer_ptr;	/* Shared buffer. */

void
shmem_setup(void)
{

	shmem_metadata_ptr = mmap(MAP_ANON, getpagesize(), ..);
	if (shmem_metadata_ptr == MAP_FAILED)
		xo_err(EX_OSERR, "mmap")

	shmem_buffer_ptr = mmap(MAP_ANON, roundup(buffersize, getpagesize()),
	    ..);
	if (shmem_buffer_ptr == MAP_FAILED)
		xo_err(EX_OSERR, "mmap")

	/* If across fork(). */
	if (minherit(shmem_metadta_ptr, getpagesize(), INHERIT_SHARE) < 0)
		xo_err(EX_OSERR, "minherit");

	if (minherit(shmem_buffer_ptr, getpagesize(), INHERIT_SHARE) < 0)
		xo_err(EX_OSERR, "minherit");


}

void
shmem_teardown(void)
{

	if (munmap(shmem_buffer_ptr, roundup(buffersize, getpagesize())) < 0)
		xo_err(EX_OSERR, "munmap");
	if (munmap(shmem_metadata_ptr, getpagesize()) < 0)
		xo_err(EX_OSERR, "munmap");
}
