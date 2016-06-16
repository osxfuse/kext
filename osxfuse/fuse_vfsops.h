/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2010 Tuxera Inc.
 * All rights reserved.
 */

#ifndef _FUSE_VFSOPS_H_
#define _FUSE_VFSOPS_H_

#include "fuse.h"

struct fuse_data;
struct fuse_ticket;

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK
extern struct vnodeopv_entry_desc fuse_biglock_vnode_operation_entries[];
#else
extern struct vnodeopv_entry_desc fuse_vnode_operation_entries[];
#endif

#if M_OSXFUSE_ENABLE_SPECFS
extern struct vnodeopv_entry_desc fuse_spec_operation_entries[];
#endif

#if M_OSXFUSE_ENABLE_FIFOFS
extern struct vnodeopv_entry_desc fuse_fifo_operation_entries[];
#endif

/* VFS operations */

static errno_t
fuse_vfsop_mount(mount_t mp, vnode_t devvp, user_addr_t data,
                 vfs_context_t context);

static errno_t
fuse_vfsop_unmount(mount_t mp, int mntflags, vfs_context_t context);

static errno_t
fuse_vfsop_root(mount_t mp, vnode_t *vpp, vfs_context_t context);

static errno_t
fuse_vfsop_getattr(mount_t mp, struct vfs_attr *attr, vfs_context_t context);

static errno_t
fuse_vfsop_sync(mount_t mp, int waitfor, vfs_context_t context);

static errno_t
fuse_vfsop_setattr(mount_t mp, struct vfs_attr *fsap,
                   __unused vfs_context_t context);

/* Other VFS operations */

extern int
fuse_setextendedsecurity(mount_t mp, int state);

#endif /* _FUSE_VFSOPS_H_ */
