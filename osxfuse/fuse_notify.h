/*
 * Copyright (c) 2012-2017 Benjamin Fleischer
 * All rights reserved.
 */

#ifndef _FUSE_NOTIFY_H_
#define _FUSE_NOTIFY_H_

#include "fuse.h"

#include "fuse_ipc.h"

#include <fuse_param.h>

/*
 * Note: The following vnode event flags are kernel-private, therefore we need
 * to define them here. The flags need to be kept in sync with those defined in
 * bsd/sys/vnode.h.
 *
 * FUSE_VNODE_EVENT_DELETE
 *     file was removed
 *
 * FUSE_VNODE_EVENT_WRITE
 *     file or directory contents changed
 *
 * FUSE_VNODE_EVENT_EXTEND
 *     ubc size increased
 *
 * FUSE_VNODE_EVENT_ATTRIB
 *     attributes changed (suitable for permission changes if type unknown)
 *
 * FUSE_VNODE_EVENT_LINK
 *     link count changed
 *
 * FUSE_VNODE_EVENT_RENAME
 *     vnode was renamed
 *
 * FUSE_VNODE_EVENT_PERMS
 *     permissions changed: will cause a NOTE_ATTRIB
 *
 * FUSE_VNODE_EVENT_FILE_CREATED
 *     file created in directory, will cause NOTE_WRITE
 *
 * FUSE_VNODE_EVENT_DIR_CREATED
 *     directory created inside this directory, will cause NOTE_WRITE
 *
 * FUSE_VNODE_EVENT_FILE_REMOVED
 *     file removed from this directory, will cause NOTE_WRITE
 *
 * FUSE_VNODE_EVENT_DIR_REMOVED
 *     subdirectory from this directory, will cause NOTE_WRITE
 */

#define FUSE_VNODE_EVENT_DELETE         0x00000001
#define FUSE_VNODE_EVENT_WRITE          0x00000002
#define FUSE_VNODE_EVENT_EXTEND         0x00000004
#define FUSE_VNODE_EVENT_ATTRIB         0x00000008
#define FUSE_VNODE_EVENT_LINK           0x00000010
#define FUSE_VNODE_EVENT_RENAME         0x00000020
#define FUSE_VNODE_EVENT_PERMS          0x00000040
#define FUSE_VNODE_EVENT_FILE_CREATED   0x00000080
#define FUSE_VNODE_EVENT_DIR_CREATED    0x00000100
#define FUSE_VNODE_EVENT_FILE_REMOVED   0x00000200
#define FUSE_VNODE_EVENT_DIR_REMOVED    0x00000400

int fuse_vnode_notify(vnode_t vp, uint32_t events);

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK

int fuse_notify_inval_entry(struct fuse_data *data, struct fuse_iov *iov);
int fuse_notify_inval_inode(struct fuse_data *data, struct fuse_iov *iov);
int fuse_notify_delete(struct fuse_data *data, struct fuse_iov *iov);

#endif /* M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */

#endif /* _FUSE_NOTIFY_H_ */
