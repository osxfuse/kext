/*
 * Copyright (C) 2006-2007 Google. All Rights Reserved.
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

struct fuse_selinfo {
    unsigned char __data[32];
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

struct fuse_kludge_vnode {
    char    dummy0[112];
    char   *v_name;
    vnode_t v_parent;
    char    dummy1[12];
};

extern void fuse_kludge_exchange(vnode_t v1, vnode_t v2);

#endif /* M_MACFUSE_ENABLE_EXCHANGE */

#endif /* _FUSE_KLUDGES_H_ */
