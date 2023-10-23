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

#ifndef IPC_H
#define	IPC_H

/*
 * Front end of the benchmark called from main().
 */
void	ipc(void);

/*
 * APIs for file-descriptor-based and shared-memory-based IPC.
 */
struct sender_argument {
	struct timespec	 sa_starttime;	/* Sender stores start time here. */
	intptr_t	 sa_write_handle; /* Caller provides send fd here. */
	long		 sa_msgcount;	/* Caller provides msg count here. */
	void		*sa_buffer;	/* Caller provides buffer here. */
}; 
 
void	sender_fd(struct sender_argument *sap);
void	receiver_fd(intptr_t readfd, void *buf);
void	ipc_objects_allocate_fd(intptr_t *read_handlep,
	    intptr_t *write_handlep);
void	ipc_objects_free_fd(intptr_t read_handle, intptr_t write_handle);

void	sender_shmem(struct sender_argument *sap);
void	receiver_shmem(intptr_t readfd, void *buf);
void	ipc_objects_allocate_shmem(intptr_t *read_handlep,
	    intptr_t *write_handlep);
void	ipc_objects_free_shmem(intptr_t read_handle, intptr_t write_handle);

#endif /* IPC_H */
