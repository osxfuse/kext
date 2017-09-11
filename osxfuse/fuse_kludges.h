/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2012 Tuxera Inc.
 * Copyright (c) 2012-2016 Benjamin Fleischer
 * All rights reserved.
 */

#ifndef _FUSE_KLUDGES_H_
#define _FUSE_KLUDGES_H_

#include "fuse.h"

#include <stdbool.h>

/*
 * The shop of horrors
 */

#if M_OSXFUSE_ENABLE_DSELECT

/*
 * sizeof(struct selinfo)
 *
 *     10.5               24
 *     10.6    i386       24
 *     10.6    x86_64     48
 *     10.11              64
 */

struct fuse_selinfo {
    unsigned char dummy[64];
};

#endif /* M_OSXFUSE_ENABLE_DSELECT */

/*
 * offsetof(thread_t, sched_flags)
 *
 *     10.7    i386       88
 *     10.7    x86_64    140
 *     10.9              132
 *     10.12             136
 *     10.13             136
 */

struct fuse_kludge_thread_13 {
    char dummy[132];
    uint32_t sched_flags;
} __attribute__ ((packed));

struct fuse_kludge_thread_16
{
    char dummy[136];
    uint32_t sched_flags;
} __attribute__ ((packed));

bool fuse_kludge_thread_should_abort(thread_t th);

#endif /* _FUSE_KLUDGES_H_ */
