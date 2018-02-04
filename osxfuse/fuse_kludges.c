/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2012 Tuxera Inc.
 * Copyright (c) 2015-2018 Benjamin Fleischer
 * All rights reserved.
 */

#include "fuse_kludges.h"

#include <libkern/version.h>
#include <string.h>

typedef enum {
    FUSE_KLUDGE_KERNEL_RELEASE,
    FUSE_KLUDGE_KERNEL_DEBUG,
    FUSE_KLUDGE_KERNEL_DEVELOPMENT,
} fuse_kludge_kernel_t;

fuse_kludge_kernel_t fuse_kludge_kernel;

static
char *
fuse_strstr(const char *in, const char *str)
{
    char c;
    size_t len;
    
    c = *str++;
    if (!c) {
        return (char *)in;
    }
    
    len = strlen(str);
    do {
        char sc;
        do {
            sc = *in++;
            if (!sc) {
                return NULL;
            }
        } while (sc != c);
    } while (strncmp(in, str, len) != 0);
    
    return (char *)(in - 1);
}

void
fuse_kludge_init()
{
    /*
     * Note: There might be a better way to do detect which kernel this is,
     * but so far this is the only one we got. If the version string does
     * neither contain DEBUG nor DEVELOPMENT, we assume this is a RELEASE
     * kernel.
     */

    if (fuse_strstr(version, "DEBUG")) {
        fuse_kludge_kernel = FUSE_KLUDGE_KERNEL_DEBUG;
    } else if (fuse_strstr(version, "DEVELOPMENT")) {
        fuse_kludge_kernel = FUSE_KLUDGE_KERNEL_DEVELOPMENT;
    } else {
        fuse_kludge_kernel = FUSE_KLUDGE_KERNEL_RELEASE;
    }
}

#if VERSION_MAJOR < 10

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

/*
 * Constants from bsd/sys/vnode_internal.h.
 */
#define FUSE_KLUDGE_VL_TERMINATE    0x0004
#define FUSE_KLUDGE_VL_DEAD         0x0010

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

#endif /* VERSION_MAJOR < 10 */

__private_extern__
int
fuse_kludge_vnode_isrecycled(vnode_t vp)
{
#if VERSION_MAJOR < 10
    /*
     * Note: This hack should only be used in case of Mac OS X 10.5. Starting
     * with Mac OS X 10.6 vnode_isrecycled() is available to third party kernel
     * extensions.
     */

    lck_mtx_t *v_lock;
    uint16_t v_lflag;

    v_lock = fuse_kludge_vnode_get_v_lock(vp);

    /*
     * Note: vnode_isrecycled() uses lck_mtx_lock_spin() for i386/x86_64, but
     * this is kernel private so we can only use the 'regular' lck_mtx_lock().
     */
    lck_mtx_lock(v_lock);
    v_lflag = fuse_kludge_vnode_get_v_lflag(vp);
    lck_mtx_unlock(v_lock);

    if (v_lflag & (FUSE_KLUDGE_VL_TERMINATE | FUSE_KLUDGE_VL_DEAD)) {
        return 1;
    } else {
        return 0;
    }
#else /* VERSION_MAJOR < 10 */
    return vnode_isrecycled(vp);
#endif /* VERSION_MAJOR < 10 */
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
    uint32_t sched_flags;

    switch (fuse_kludge_kernel) {
        case FUSE_KLUDGE_KERNEL_RELEASE:
            if (version_major >= 16) {
                sched_flags = ((struct fuse_kludge_thread_16 *)th)->sched_flags;
            } else if (version_major >= 13) {
                sched_flags = ((struct fuse_kludge_thread_13 *)th)->sched_flags;
            } else if (version_major >= 11) {
                sched_flags = ((struct fuse_kludge_thread_11 *)th)->sched_flags;
            } else if (version_major >= 10) {
                sched_flags = ((struct fuse_kludge_thread_10 *)th)->sched_mode;
            } else {
                sched_flags = ((struct fuse_kludge_thread_9 *)th)->sched_mode;
            }
            break;
            
        case FUSE_KLUDGE_KERNEL_DEBUG:
            if (version_major >= 16) {
                sched_flags = ((struct fuse_kludge_thread_debug_16 *)th)->sched_flags;
            } else if (version_major >= 13) {
                sched_flags = ((struct fuse_kludge_thread_debug_13 *)th)->sched_flags;
            } else {
                sched_flags = ((struct fuse_kludge_thread_debug_11 *)th)->sched_flags;
            }
            break;
            
        case FUSE_KLUDGE_KERNEL_DEVELOPMENT:
            if (version_major >= 16) {
                sched_flags = ((struct fuse_kludge_thread_development_16 *)th)->sched_flags;
            } else {
                sched_flags = ((struct fuse_kludge_thread_development_14 *)th)->sched_flags;
            }
            break;
    }
    
    return ((sched_flags & FUSE_KLUDGE_TH_SFLAG_ABORTED_MASK) == FUSE_KLUDGE_TH_SFLAG_ABORT);
}
