/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_KLUDGES_H_
#define _FUSE_KLUDGES_H_

#include "fuse.h"

#if M_OSXFUSE_ENABLE_DSELECT

/*
 * # 10.5        10.6-32     10.6-64     10.11-64
 *
 * # sizeof(struct selinfo)
 *   24          24          48          64
 *
 */

struct fuse_selinfo {
#if __LP64__
    unsigned char __data[64];
#else
    unsigned char __data[24];
#endif
};

#endif /* M_OSXFUSE_ENABLE_DSELECT */

/* The shop of horrors. */

/*
 * # 10.5        10.6-32     10.6-64     10.7-32     10.7-64     10.9-64
 *
 * # sizeof(struct vnode)
 *   144         148         248         148         248         240
 *
 * # offsetof(struct vnode, v_lflag)
 *   48          48          88          44          80          80
 *
 * # offsetof(struct vnode, v_name)
 *   112         116         184         112         176         176
 *
 * # offsetof(struct vnode, v_parent)
 *   116         120         192         116         184         184
 */

struct fuse_kludge_vnode_9 {
    char     v_lock[12];
    char     dummy0[36];
    uint16_t v_lflag;
    char     dummy1[62];
    char    *v_name;
    vnode_t  v_parent;
    char     dummy2[24];
} __attribute__ ((packed));

#if __LP64__
struct fuse_kludge_vnode_10 {
    char     v_lock[24];
    char     dummy0[64];
    uint16_t v_lflag;
    char     dummy1[94];
    char    *v_name;
    vnode_t  v_parent;
    char     dummy2[48];
} __attribute__ ((packed));
#else
struct fuse_kludge_vnode_10 {
    char     v_lock[12];
    char     dummy0[36];
    uint16_t v_lflag;
    char     dummy1[66];
    char    *v_name;
    vnode_t  v_parent;
    char     dummy2[24];
} __attribute__ ((packed));
#endif

struct fuse_kludge_vnode_11 {
    void    *v_lock[2];
    void    *dummy0[7];
    char     dummy1[8];
    uint16_t v_lflag;
    void    *dummy2[7];
    char     dummy3[38];
    char    *v_name;
    vnode_t  v_parent;
    void    *dummy4[7];
} __attribute__ ((packed));

#if M_OSXFUSE_ENABLE_EXCHANGE

extern void fuse_kludge_exchange(vnode_t v1, vnode_t v2);

#endif /* M_OSXFUSE_ENABLE_EXCHANGE */

int fuse_kludge_vnode_isrecycled(vnode_t vp);

#endif /* _FUSE_KLUDGES_H_ */
