/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2012 Tuxera Inc.
 * Copyright (c) 2012-2016 Benjamin Fleischer
 * All rights reserved.
 */

#ifndef _FUSE_KLUDGES_H_
#define _FUSE_KLUDGES_H_

#include "fuse.h"

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
#ifdef __LP64__
    unsigned char dummy[64];
#else
    unsigned char dummy[24];
#endif
};

#endif /* M_OSXFUSE_ENABLE_DSELECT */

/*
 * sizeof(struct vnode)
 *
 *     10.5              144
 *     10.6    i386      148
 *     10.6    x86_64    248
 *     10.7    i386      148
 *     10.7    x86_64    248
 *     10.9              240
 *
 * offsetof(struct vnode, v_lflag)
 *
 *     10.5               48
 *     10.6    i386       48
 *     10.6    x86_64     88
 *     10.7    i386       44
 *     10.7    x86_64     80
 *     10.9               80
 *
 * offsetof(struct vnode, v_name)
 *
 *     10.5              112
 *     10.6    i386      116
 *     10.6    x86_64    184
 *     10.7    i386      112
 *     10.7    x86_64    176
 *     10.9              176
 *
 * offsetof(struct vnode, v_parent)
 *
 *     10.5              116
 *     10.6    i386      120
 *     10.6    x86_64    192
 *     10.7    i386      116
 *     10.7    x86_64    184
 *     10.9              184
 */

struct fuse_kludge_vnode_9
{
    char v_lock[12];
    char dummy0[36];
    uint16_t v_lflag;
    char dummy1[62];
    char *v_name;
    vnode_t v_parent;
} __attribute__ ((packed));

#ifdef __LP64__

struct fuse_kludge_vnode_10
{
    char v_lock[24];
    char dummy0[64];
    uint16_t v_lflag;
    char dummy1[94];
    char *v_name;
    vnode_t v_parent;
} __attribute__ ((packed));

#else /* __LP64__ */

struct fuse_kludge_vnode_10
{
    char v_lock[12];
    char dummy0[36];
    uint16_t v_lflag;
    char dummy1[66];
    char *v_name;
    vnode_t v_parent;
} __attribute__ ((packed));

#endif /* __LP64__ */

struct fuse_kludge_vnode_11
{
    void *v_lock[2];
    void *dummy0[7];
    char dummy1[8];
    uint16_t v_lflag;
    void *dummy2[7];
    char dummy3[38];
    char *v_name;
    vnode_t v_parent;
} __attribute__ ((packed));

int fuse_kludge_vnode_isrecycled(vnode_t vp);

/*
 * offsetof(thread_t, sched_mode)
 *
 *     10.5    ppc        96
 *     10.5    i386      152
 *     10.6    i386      152
 *     10.6    x86_64    276
 */

#ifdef __ppc__

struct fuse_kludge_thread_9
{
    char dummy[96];
    uint32_t sched_mode;
} __attribute__ ((packed));

#else /* __ppc__ */

struct fuse_kludge_thread_9
{
    char dummy[152];
    uint32_t sched_mode;
} __attribute__ ((packed));

#endif /* __ppc__ */

#ifdef __LP64__

struct fuse_kludge_thread_10
{
    char dummy[276];
    uint32_t sched_mode;
} __attribute__ ((packed));

#else /* __LP64__ */

struct fuse_kludge_thread_10
{
    char dummy[152];
    uint32_t sched_mode;
} __attribute__ ((packed));

#endif /* __LP64__ */

/*
 * offsetof(thread_t, sched_flags)
 *
 *     10.7    i386       88
 *     10.7    x86_64    140
 *     10.9              132
 *     10.12             136
 *     10.13             136
 */

#ifdef __LP64__

struct fuse_kludge_thread_11
{
    char dummy[140];
    uint32_t sched_flags;
} __attribute__ ((packed));

#else /* __LP64__ */

struct fuse_kludge_thread_11
{
    char dummy[88];
    uint32_t sched_flags;
} __attribute__ ((packed));

#endif /* __LP64__ */

struct fuse_kludge_thread_13
{
    char dummy[132];
    uint32_t sched_flags;
} __attribute__ ((packed));

struct fuse_kludge_thread_16
{
    char dummy[136];
    uint32_t sched_flags;
} __attribute__ ((packed));

boolean_t fuse_kludge_thread_should_abort(thread_t th);

#endif /* _FUSE_KLUDGES_H_ */
