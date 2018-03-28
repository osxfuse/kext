/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2012 Tuxera Inc.
 * Copyright (c) 2012-2018 Benjamin Fleischer
 * All rights reserved.
 */

#ifndef _FUSE_KLUDGES_H_
#define _FUSE_KLUDGES_H_

#include "fuse.h"

#include <stdbool.h>

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

struct fuse_kludge_selinfo {
#ifdef __LP64__
    unsigned char dummy[64];
#else
    unsigned char dummy[24];
#endif
};

#endif /* M_OSXFUSE_ENABLE_DSELECT */

void fuse_kludge_init();
void fuse_kludge_exchange(vnode_t vp1, vnode_t vp2);
int fuse_kludge_vnode_isrecycled(vnode_t vp);
bool fuse_kludge_thread_should_abort(thread_t th);

#endif /* _FUSE_KLUDGES_H_ */
