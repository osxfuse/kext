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
 *     10.12             184
 *
 * offsetof(struct vnode, v_parent)
 *
 *     10.5              116
 *     10.6    i386      120
 *     10.6    x86_64    192
 *     10.7    i386      116
 *     10.7    x86_64    184
 *     10.9              184
 *     10.12             192
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

struct fuse_kludge_vnode_16
{
    char dummy3[184];
    char *v_name;
    vnode_t v_parent;
} __attribute__ ((packed));

__private_extern__
void
fuse_kludge_exchange(vnode_t vp1, vnode_t vp2)
{
    if (version_major > 15) {
        char *tmp_v_name = ((struct fuse_kludge_vnode_16 *)vp1)->v_name;
        ((struct fuse_kludge_vnode_16 *)vp1)->v_name =
        ((struct fuse_kludge_vnode_16 *)vp2)->v_name;
        ((struct fuse_kludge_vnode_16 *)vp2)->v_name = tmp_v_name;

        vnode_t tmp_v_parent = ((struct fuse_kludge_vnode_16 *)vp1)->v_parent;
        ((struct fuse_kludge_vnode_16 *)vp1)->v_parent =
        ((struct fuse_kludge_vnode_16 *)vp2)->v_parent;
        ((struct fuse_kludge_vnode_16 *)vp2)->v_parent = tmp_v_parent;

    } else if (version_major > 10) {
        char *tmp_v_name = ((struct fuse_kludge_vnode_11 *)vp1)->v_name;
        ((struct fuse_kludge_vnode_11 *)vp1)->v_name =
        ((struct fuse_kludge_vnode_11 *)vp2)->v_name;
        ((struct fuse_kludge_vnode_11 *)vp2)->v_name = tmp_v_name;

        vnode_t tmp_v_parent = ((struct fuse_kludge_vnode_11 *)vp1)->v_parent;
        ((struct fuse_kludge_vnode_11 *)vp1)->v_parent =
        ((struct fuse_kludge_vnode_11 *)vp2)->v_parent;
        ((struct fuse_kludge_vnode_11 *)vp2)->v_parent = tmp_v_parent;

    } else if (version_major > 9) {
        char *tmp_v_name = ((struct fuse_kludge_vnode_10 *)vp1)->v_name;
        ((struct fuse_kludge_vnode_10 *)vp1)->v_name =
        ((struct fuse_kludge_vnode_10 *)vp2)->v_name;
        ((struct fuse_kludge_vnode_10 *)vp2)->v_name = tmp_v_name;

        vnode_t tmp_v_parent = ((struct fuse_kludge_vnode_10 *)vp1)->v_parent;
        ((struct fuse_kludge_vnode_10 *)vp1)->v_parent =
        ((struct fuse_kludge_vnode_10 *)vp2)->v_parent;
        ((struct fuse_kludge_vnode_10 *)vp2)->v_parent = tmp_v_parent;

    } else {
        char *tmp_v_name = ((struct fuse_kludge_vnode_9 *)vp1)->v_name;
        ((struct fuse_kludge_vnode_9 *)vp1)->v_name =
        ((struct fuse_kludge_vnode_9 *)vp2)->v_name;
        ((struct fuse_kludge_vnode_9 *)vp2)->v_name = tmp_v_name;

        vnode_t tmp_v_parent = ((struct fuse_kludge_vnode_9 *)vp1)->v_parent;
        ((struct fuse_kludge_vnode_9 *)vp1)->v_parent =
        ((struct fuse_kludge_vnode_9 *)vp2)->v_parent;
        ((struct fuse_kludge_vnode_9 *)vp2)->v_parent = tmp_v_parent;
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
 * RELEASE kernel
 *     10.7    i386       88
 *     10.7    x86_64    140
 *     10.9              132
 *     10.12             136
 *     10.14             168
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

struct fuse_kludge_thread_18
{
    char dummy[168];
    uint32_t sched_flags;
} __attribute__ ((packed));

/*
 * offsetof(thread_t, sched_flags)
 *
 * DEBUG kernel
 *     10.7    i386      152
 *     10.7    x86_64    268
 *     10.9              260
 *     10.12             272
 *     10.14             304
 */

#ifdef __LP64__

struct fuse_kludge_thread_debug_11
{
    char dummy[268];
    uint32_t sched_flags;
} __attribute__ ((packed));

#else /* __LP64__ */

struct fuse_kludge_thread_debug_11
{
    char dummy[152];
    uint32_t sched_flags;
} __attribute__ ((packed));

#endif /* __LP64__ */

struct fuse_kludge_thread_debug_13
{
    char dummy[260];
    uint32_t sched_flags;
} __attribute__ ((packed));

struct fuse_kludge_thread_debug_16
{
    char dummy[272];
    uint32_t sched_flags;
} __attribute__ ((packed));

struct fuse_kludge_thread_debug_18
{
    char dummy[304];
    uint32_t sched_flags;
} __attribute__ ((packed));

/*
 * offsetof(thread_t, sched_flags)
 *
 * DEVELOPMENT kernel
 *     10.10             132
 *     10.12             144
 *     10.14             176
 */

struct fuse_kludge_thread_development_14
{
    char dummy[132];
    uint32_t sched_flags;
} __attribute__ ((packed));

struct fuse_kludge_thread_development_16
{
    char dummy[144];
    uint32_t sched_flags;
} __attribute__ ((packed));

struct fuse_kludge_thread_development_18
{
    char dummy[176];
    uint32_t sched_flags;
} __attribute__ ((packed));

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
            if (version_major >= 18) {
                sched_flags = ((struct fuse_kludge_thread_18 *)th)->sched_flags;
            } else if (version_major >= 16) {
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
            if (version_major >= 18) {
                sched_flags = ((struct fuse_kludge_thread_debug_18 *)th)->sched_flags;
            } else if (version_major >= 16) {
                sched_flags = ((struct fuse_kludge_thread_debug_16 *)th)->sched_flags;
            } else if (version_major >= 13) {
                sched_flags = ((struct fuse_kludge_thread_debug_13 *)th)->sched_flags;
            } else {
                sched_flags = ((struct fuse_kludge_thread_debug_11 *)th)->sched_flags;
            }
            break;

        case FUSE_KLUDGE_KERNEL_DEVELOPMENT:
            if (version_major >= 18) {
                sched_flags = ((struct fuse_kludge_thread_development_18 *)th)->sched_flags;
            } else if (version_major >= 16) {
                sched_flags = ((struct fuse_kludge_thread_development_16 *)th)->sched_flags;
            } else {
                sched_flags = ((struct fuse_kludge_thread_development_14 *)th)->sched_flags;
            }
            break;
    }

    return ((sched_flags & FUSE_KLUDGE_TH_SFLAG_ABORTED_MASK) == FUSE_KLUDGE_TH_SFLAG_ABORT);
}
