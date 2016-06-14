/*
 * Copyright (c) 2012 Benjamin Fleischer
 * All rights reserved.
 */

#ifndef _FUSE_NOTIFY_H_
#define _FUSE_NOTIFY_H_

#include "fuse.h"

#include "fuse_ipc.h"

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK

int fuse_notify_inval_entry(struct fuse_data *data, struct fuse_iov *iov);
int fuse_notify_inval_inode(struct fuse_data *data, struct fuse_iov *iov);

#endif /* M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */

#endif /* _FUSE_NOTIFY_H_ */
