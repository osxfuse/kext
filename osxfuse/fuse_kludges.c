/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2012 Tuxera Inc.
 * Copyright (c) 2015-2017 Benjamin Fleischer
 * All rights reserved.
 */

#include "fuse_kludges.h"

#include <libkern/version.h>

FUSE_INLINE
lck_mtx_t *
fuse_kludge_vnode_get_v_lock(vnode_t vp)
{
    if (version_major >= 11) {
        return (lck_mtx_t *)((struct fuse_kludge_vnode_11 *)vp)->v_lock;
    } else if (version_major >= 10) {
        return (lck_mtx_t *)((struct fuse_kludge_vnode_10 *)vp)->v_lock;
    } else {
        return (lck_mtx_t *)((struct fuse_kludge_vnode_9 *)vp)->v_lock;
    }
}

FUSE_INLINE
uint16_t
fuse_kludge_vnode_get_v_lflag(vnode_t vp)
{
    if (version_major >= 11) {
        return ((struct fuse_kludge_vnode_11 *)vp)->v_lflag;
    } else if (version_major >= 10) {
        return ((struct fuse_kludge_vnode_10 *)vp)->v_lflag;
    } else {
        return ((struct fuse_kludge_vnode_9 *)vp)->v_lflag;
    }
}

/*
 * Constants from bsd/sys/vnode_internal.h.
 */
#define FUSE_KLUDGE_VL_TERMINATE    0x0004
#define FUSE_KLUDGE_VL_DEAD         0x0010

__private_extern__
int
fuse_kludge_vnode_isrecycled(vnode_t vp)
{
#if VERSION_MAJOR < 10
    lck_mtx_t *v_lock;
    uint16_t v_lflag;

    v_lock = fuse_kludge_vnode_get_v_lock(vp);

    /*
     * Note: In 10.5 and later vnode_isrecycled uses lck_mtx_lock_spin for
     * i386/x86_64, but this is kernel private so we can only use 'regular'
     * lck_mtx_lock.
     */
    lck_mtx_lock(v_lock);
    v_lflag = fuse_kludge_vnode_get_v_lflag(vp);
    lck_mtx_unlock(v_lock);

    return (v_lflag & (FUSE_KLUDGE_VL_TERMINATE | FUSE_KLUDGE_VL_DEAD)) ? 1 : 0;
#else
    return vnode_isrecycled(vp);
#endif
}

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
    uint32_t sched_mode;

    if (version_major >= 16) {
        sched_mode = ((struct fuse_kludge_thread_16 *)th)->sched_flags;
    } else if (version_major >= 13) {
        sched_mode = ((struct fuse_kludge_thread_13 *)th)->sched_flags;
    } else if (version_major >= 11) {
        sched_mode = ((struct fuse_kludge_thread_11 *)th)->sched_flags;
    } else if (version_major >= 10) {
        sched_mode = ((struct fuse_kludge_thread_10 *)th)->sched_mode;
    } else {
        sched_mode = ((struct fuse_kludge_thread_9 *)th)->sched_mode;
    }

    return ((sched_mode & FUSE_KLUDGE_TH_SFLAG_ABORTED_MASK) == FUSE_KLUDGE_TH_SFLAG_ABORT);
}
