/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#include "fuse_kludges.h"
#include <libkern/version.h>

#if M_MACFUSE_ENABLE_EXCHANGE

extern void
fuse_kludge_exchange(vnode_t v1, vnode_t v2)
{
    if (version_major > 9) {
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

#endif /* M_MACFUSE_ENABLE_EXCHANGE */
