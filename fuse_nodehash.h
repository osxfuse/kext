/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

/*
 * Portions Copyright (c) 1999-2003 Apple Computer, Inc. All Rights Reserved.
 *
 * This file contains Original Code and/or Modifications of Original Code as
 * defined in and that are subject to the Apple Public Source License Version
 * 2.0 (the 'License'). You may not use this file except in compliance with
 * the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. Please see
 * the License for the specific language governing rights and limitations
 * under the License.
 */

#ifndef _FUSE_NODEHASH_H_
#define _FUSE_NODEHASH_H_

#include <stdint.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <libkern/OSMalloc.h>

#include "fuse_device.h"

typedef struct HNode * HNodeRef;

extern errno_t HNodeInit(lck_grp_t   *lockGroup, 
                         lck_attr_t  *lockAttr, 
                         OSMallocTag  mallocTag, 
                         uint32_t     magic, 
                         size_t       fsNodeSize);
extern void HNodeTerm(void);

extern void *    FSNodeGenericFromHNode(HNodeRef hnode);
extern HNodeRef  HNodeFromFSNodeGeneric(void *fsNode);
extern HNodeRef  HNodeFromVNode(vnode_t vn);
extern void *    FSNodeGenericFromVNode(vnode_t vn);

extern fuse_device_t HNodeGetDevice(HNodeRef hnode);
extern uint64_t      HNodeGetInodeNumber(HNodeRef hnode);
extern vnode_t       HNodeGetVNodeForForkAtIndex(HNodeRef hnode,
                                                 size_t forkIndex);
extern size_t        HNodeGetForkIndexForVNode(vnode_t vn);
extern void          HNodeExchangeFromFSNode(void *fsnode1, void *fsnode2);

extern errno_t   HNodeLookupRealQuickIfExists(fuse_device_t dev,
                                              uint64_t      ino,
                                              size_t        forkIndex,
                                              HNodeRef     *hnodePtr,
                                              vnode_t      *vnPtr);
extern errno_t   HNodeLookupCreatingIfNecessary(fuse_device_t dev,
                                                uint64_t      ino,
                                                size_t        forkIndex,
                                                HNodeRef     *hnodePtr,
                                                vnode_t      *vnPtr);
extern void      HNodeAttachVNodeSucceeded(HNodeRef hnode,
                                           size_t   forkIndex,
                                           vnode_t  vn);
extern boolean_t HNodeAttachVNodeFailed(HNodeRef hnode, size_t forkIndex);
extern boolean_t HNodeDetachVNode(HNodeRef hnode, vnode_t vn);
extern void      HNodeScrubDone(HNodeRef hnode);

void             HNodePrintState(void);

#endif /* _FUSE_NODEHASH_H_ */
