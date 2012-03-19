/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2012 Tuxera Inc.
 * All rights reserved.
 */

#include "fuse_kludges.h"

#include <libkern/version.h>

#if M_OSXFUSE_ENABLE_EXCHANGE

extern void
fuse_kludge_exchange(vnode_t v1, vnode_t v2)
{
    if (version_major > 10) {
        char *tmp_v_name = ((struct fuse_kludge_vnode_11 *)v1)->v_name;
        ((struct fuse_kludge_vnode_11 *)v1)->v_name =
            ((struct fuse_kludge_vnode_11 *)v2)->v_name;
        ((struct fuse_kludge_vnode_11 *)v2)->v_name = tmp_v_name;

        vnode_t tmp_v_parent = ((struct fuse_kludge_vnode_11 *)v1)->v_parent;
        ((struct fuse_kludge_vnode_11 *)v1)->v_parent =
            ((struct fuse_kludge_vnode_11 *)v2)->v_parent;
        ((struct fuse_kludge_vnode_11 *)v2)->v_parent = tmp_v_parent;
    }
    else if (version_major > 9) {
        char *tmp_v_name = ((struct fuse_kludge_vnode_10 *)v1)->v_name;
        ((struct fuse_kludge_vnode_10 *)v1)->v_name =
            ((struct fuse_kludge_vnode_10 *)v2)->v_name;
        ((struct fuse_kludge_vnode_10 *)v2)->v_name = tmp_v_name;

        vnode_t tmp_v_parent = ((struct fuse_kludge_vnode_10 *)v1)->v_parent;
        ((struct fuse_kludge_vnode_10 *)v1)->v_parent =
            ((struct fuse_kludge_vnode_10 *)v2)->v_parent;
        ((struct fuse_kludge_vnode_10 *)v2)->v_parent = tmp_v_parent;
    } else {
        char *tmp_v_name = ((struct fuse_kludge_vnode_9 *)v1)->v_name;
        ((struct fuse_kludge_vnode_9 *)v1)->v_name =
            ((struct fuse_kludge_vnode_9 *)v2)->v_name;
        ((struct fuse_kludge_vnode_9 *)v2)->v_name = tmp_v_name;

        vnode_t tmp_v_parent = ((struct fuse_kludge_vnode_9 *)v1)->v_parent;
        ((struct fuse_kludge_vnode_9 *)v1)->v_parent =
            ((struct fuse_kludge_vnode_9 *)v2)->v_parent;
        ((struct fuse_kludge_vnode_9 *)v2)->v_parent = tmp_v_parent;
    }
}

#endif /* M_OSXFUSE_ENABLE_EXCHANGE */

static inline lck_mtx_t* fuse_kludge_vnode_get_v_lock(vnode_t vp)
{
    if(version_major >= 11)
        return (lck_mtx_t*) (((struct fuse_kludge_vnode_11*) vp)->v_lock);
    else if(version_major >= 10)
        return (lck_mtx_t*) (((struct fuse_kludge_vnode_10*) vp)->v_lock);
    else
        return (lck_mtx_t*) (((struct fuse_kludge_vnode_9*) vp)->v_lock);
}

static inline uint16_t fuse_kludge_vnode_get_v_lflag(vnode_t vp)
{
    if(version_major >= 11)
        return ((struct fuse_kludge_vnode_11*) vp)->v_lflag;
    else if(version_major >= 10)
        return ((struct fuse_kludge_vnode_10*) vp)->v_lflag;
    else
        return ((struct fuse_kludge_vnode_9*) vp)->v_lflag;
}

/* Constants from vnode_internal.h. */
#define FUSE_KLUDGE_VL_TERMINATE    0x0004
#define FUSE_KLUDGE_VL_DEAD         0x0010

__private_extern__ int fuse_kludge_vnode_isrecycled(vnode_t vp)
{
    lck_mtx_t *v_lock;
    uint16_t v_lflag;

    v_lock = fuse_kludge_vnode_get_v_lock(vp);

    /* Note: In 10.5 and later vnode_isrecycled uses lck_mtx_lock_spin for
     * i386/x86_64, but this is kernel private so we can only use 'regular'
     * lck_mtx_lock. */
    lck_mtx_lock(v_lock);
    v_lflag = fuse_kludge_vnode_get_v_lflag(vp);
    lck_mtx_unlock(v_lock);

    return (v_lflag & (FUSE_KLUDGE_VL_TERMINATE | FUSE_KLUDGE_VL_DEAD)) ? 1 : 0;
}
