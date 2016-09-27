/*
 * Copyright (c) 2016 EditShare LLC
 * All rights reserved.
 */

#ifndef _FUSE_FSEVENTS_H_
#define _FUSE_FSEVENTS_H_

#include "fuse.h"

#include <libkern/version.h>

#define VNODE_EVENT_DELETE 0x00000001
#define VNODE_EVENT_WRITE  0x00000002
#define VNODE_EVENT_EXTEND 0x00000004
#define VNODE_EVENT_ATTRIB 0x00000008
#define VNODE_EVENT_LINK   0x00000010
#define VNODE_EVENT_RENAME 0x00000020

#if VERSION_MAJOR >= 15
#define FUSE_FSEVENT(vp, hint) fsevent(vp, hint)
extern void fsevent(vnode_t vp, uint32_t hint);
#else
#define FUSE_FSEVENT(vp, hint) do {} while(0)
#endif

#endif /* _FUSE_FSEVENT_H_ */
