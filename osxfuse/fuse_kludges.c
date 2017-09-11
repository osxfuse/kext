/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2012 Tuxera Inc.
 * Copyright (c) 2015-2016 Benjamin Fleischer
 * All rights reserved.
 */

#include "fuse_kludges.h"

#include <libkern/version.h>

/*
 * Constants from osfmk/kern/thread.h
 */
#define FUSE_KLUDGE_TH_SFLAG_ABORT          0x0010
#define FUSE_KLUDGE_TH_SFLAG_ABORTSAFELY    0x0020
#define FUSE_KLUDGE_TH_SFLAG_ABORTED_MASK   (FUSE_KLUDGE_TH_SFLAG_ABORT | FUSE_KLUDGE_TH_SFLAG_ABORTSAFELY)

__private_extern__
bool
fuse_kludge_thread_should_abort(thread_t th)
{
    uint32_t sched_flags;

    if (version_major >= 16) {
        sched_flags = ((struct fuse_kludge_thread_16 *)th)->sched_flags;
    } else {
        sched_flags = ((struct fuse_kludge_thread_13 *)th)->sched_flags;
    }

    return ((sched_flags & FUSE_KLUDGE_TH_SFLAG_ABORTED_MASK) == FUSE_KLUDGE_TH_SFLAG_ABORT);
}
