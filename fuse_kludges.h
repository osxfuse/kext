/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_KLUDGES_H_
#define _FUSE_KLUDGES_H_

#include "fuse.h"
#include "fuse_sysctl.h"

#include <sys/cdefs.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/vnode.h>

#if M_MACFUSE_ENABLE_DSELECT

/*
 * # 10.5        10.6-32        10.6-64
 *
 * # sizeof(struct selinfo)
 *   24          24             48
 *
 */

struct fuse_selinfo {
#if __LP64__
    unsigned char __data[48];
#else
    unsigned char __data[32];
#endif
};

#define POLLIN          0x0001          /* any readable data available */
#define POLLPRI         0x0002          /* OOB/Urgent readable data */
#define POLLOUT         0x0004          /* file descriptor is writeable */
#define POLLRDNORM      0x0040          /* non-OOB/URG data available */
#define POLLWRNORM      POLLOUT         /* no write type differentiation */
#define POLLRDBAND      0x0080          /* OOB/Urgent readable data */
#define POLLWRBAND      0x0100          /* OOB/Urgent data can be written */

#endif /* M_MACFUSE_ENABLE_DSELECT */

#if M_MACFUSE_ENABLE_EXCHANGE

/* The shop of horrors. */

/*
 * # 10.5        10.6-32        10.6-64
 *
 * # sizeof(struct vnode)
 *   144         148            248
 *
 * # offsetof(struct vnode, v_lflag)
 *   48          48             88
 *
 * # offsetof(struct vnode, v_name)
 *   112         116            184
 *
 * # offsetof(struct vnode, v_parent)
 *   116         120            192
 */

struct fuse_kludge_vnode_9 {
    char     dummy0[48];
    uint16_t v_lflag;
    char     dummy1[62];
    char    *v_name;
    vnode_t  v_parent;
    char     dummy2[24];
} __attribute__ ((packed));

#if __LP64__
struct fuse_kludge_vnode_10 {
    char     dummy0[88];
    uint16_t v_lflag;
    char     dummy1[94];
    char    *v_name;
    vnode_t  v_parent;
    char     dummy2[48];
} __attribute__ ((packed));
#else
struct fuse_kludge_vnode_10 {
    char     dummy0[48];
    uint16_t v_lflag;
    char     dummy1[66];
    char    *v_name;
    vnode_t  v_parent;
    char     dummy2[24];
} __attribute__ ((packed));
#endif

extern void fuse_kludge_exchange(vnode_t v1, vnode_t v2);

#endif /* M_MACFUSE_ENABLE_EXCHANGE */

#endif /* _FUSE_KLUDGES_H_ */
