/*
 * Copyright (C) 2006 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#ifndef _FUSE_VNOPS_H_
#define _FUSE_VNOPS_H_

#include <fuse_param.h>

typedef int (*fuse_vnode_op_t)(void *);

#if M_MACFUSE_ENABLE_SPECFS
typedef int (*fuse_spec_op_t)(void *);
#endif

static int fuse_vnop_access(struct vnop_access_args *ap);

// static int fuse_vnop_advlock(struct vnop_advlock_args *ap);

// static int fuse_vnop_allocate(struct vnop_allocate_args *ap);

static int fuse_vnop_blktooff(struct vnop_blktooff_args *ap);

static int fuse_vnop_blockmap(struct vnop_blockmap_args *ap);

// static int fuse_vnop_bwrite(struct vnop_bwrite_args *ap);

static int fuse_vnop_close(struct vnop_close_args *ap);

// static int fuse_vnop_copyfile(struct vnop_copyfile_args *ap);

static int fuse_vnop_create(struct vnop_create_args *ap);

// static int fuse_vnop_exchange(struct vnop_exchange_args *ap);

static int fuse_vnop_fsync(struct vnop_fsync_args *ap);

static int fuse_vnop_getattr(struct vnop_getattr_args *ap);

// static int fuse_vnop_getattrlist(struct vnop_getattrlist_args *ap);

#if M_MACFUSE_ENABLE_XATTR
static int fuse_vnop_getxattr(struct vnop_getxattr_args *ap);
#endif

static int fuse_vnop_inactive(struct vnop_inactive_args *ap);

static int fuse_vnop_ioctl(struct vnop_ioctl_args *ap);

#if M_MACFUSE_ENABLE_KQUEUE
static int fuse_vnop_kqfilt_add(struct vnop_kqfilt_add_args *ap);

static int fuse_vnop_kqfilt_remove(struct vnop_kqfilt_remove_args *ap);
#endif

static int fuse_vnop_link(struct vnop_link_args *ap);

#if M_MACFUSE_ENABLE_XATTR
static int fuse_vnop_listxattr(struct vnop_listxattr_args *ap);
#endif

static int fuse_vnop_lookup(struct vnop_lookup_args *ap);

static int fuse_vnop_mkdir(struct vnop_mkdir_args *ap);

static int fuse_vnop_mknod(struct vnop_mknod_args *ap);

static int fuse_vnop_mmap(struct vnop_mmap_args *ap);

static int fuse_vnop_mnomap(struct vnop_mnomap_args *ap);

static int fuse_vnop_offtoblk(struct vnop_offtoblk_args *ap);

static int fuse_vnop_open(struct vnop_open_args *ap);

static int fuse_vnop_pagein(struct vnop_pagein_args *ap);

static int fuse_vnop_pageout(struct vnop_pageout_args *ap);

static int fuse_vnop_pathconf(struct vnop_pathconf_args *ap);

static int fuse_vnop_read(struct vnop_read_args *ap);

static int fuse_vnop_readdir(struct vnop_readdir_args *ap);

// static int fuse_vnop_readdirattr(struct vnop_readdirattr_args *ap);

static int fuse_vnop_readlink(struct vnop_readlink_args *ap);

static int fuse_vnop_reclaim(struct vnop_reclaim_args *ap);

static int fuse_vnop_remove(struct vnop_remove_args *ap);

#if M_MACFUSE_ENABLE_XATTR
static int fuse_vnop_removexattr(struct vnop_removexattr_args *ap);
#endif

static int fuse_vnop_rename(struct vnop_rename_args *ap);

static int fuse_vnop_revoke(struct vnop_revoke_args *ap);

static int fuse_vnop_rmdir(struct vnop_rmdir_args *ap);

// static int fuse_vnop_searchfs(struct vnop_searchfs_args *ap);

static int fuse_vnop_select(struct vnop_select_args *ap);

static int fuse_vnop_setattr(struct vnop_setattr_args *ap);

// static int fuse_vnop_setattrlist (struct vnop_setattrlist_args *ap);

#if M_MACFUSE_ENABLE_XATTR
static int fuse_vnop_setxattr(struct vnop_setxattr_args *ap);
#endif

static int fuse_vnop_strategy(struct vnop_strategy_args *ap);

static int fuse_vnop_symlink(struct vnop_symlink_args *ap);

// static int fuse_vnop_whiteout(struct vnop_whiteout_args *ap);

static int fuse_vnop_write(struct vnop_write_args *ap);

/* specfs */

int     spec_ebadf(void *);
int     spec_lookup (struct vnop_lookup_args *);
#define spec_create (int (*) (struct  vnop_access_args *))err_create
#define spec_mknod (int (*) (struct  vnop_access_args *))err_mknod
int     spec_open (struct vnop_open_args *);
int     spec_close (struct vnop_close_args *);
#define spec_access (int (*) (struct  vnop_access_args *))spec_ebadf
#define spec_getattr (int (*) (struct  vnop_getattr_args *))spec_ebadf
#define spec_setattr (int (*) (struct  vnop_setattr_args *))spec_ebadf
int     spec_read (struct vnop_read_args *);
int     spec_write (struct vnop_write_args *);
int     spec_ioctl (struct vnop_ioctl_args *);
int     spec_select (struct vnop_select_args *);
#define spec_revoke (int (*) (struct  vnop_access_args *))nop_revoke
#define spec_mmap (int (*) (struct  vnop_access_args *))err_mmap
int     spec_fsync (struct  vnop_fsync_args *);
int     spec_fsync_internal (vnode_t, int, vfs_context_t);
#define spec_remove (int (*) (struct  vnop_access_args *))err_remove
#define spec_link (int (*) (struct  vnop_access_args *))err_link
#define spec_rename (int (*) (struct  vnop_access_args *))err_rename
#define spec_mkdir (int (*) (struct  vnop_access_args *))err_mkdir
#define spec_rmdir (int (*) (struct  vnop_access_args *))err_rmdir
#define spec_symlink (int (*) (struct  vnop_access_args *))err_symlink
#define spec_readdir (int (*) (struct  vnop_access_args *))err_readdir
#define spec_readlink (int (*) (struct  vnop_access_args *))err_readlink
#define spec_inactive (int (*) (struct  vnop_access_args *))nop_inactive
#define spec_reclaim (int (*) (struct  vnop_access_args *))nop_reclaim
#define spec_lock (int (*) (struct  vnop_access_args *))nop_lock
#define spec_unlock (int (*)(struct  vnop_access_args *))nop_unlock
int     spec_strategy (struct vnop_strategy_args *);
#define spec_islocked (int (*) (struct  vnop_access_args *))nop_islocked
int     spec_pathconf (struct vnop_pathconf_args *);
#define spec_advlock (int (*) (struct  vnop_access_args *))err_advlock
#define spec_blkatoff (int (*) (struct  vnop_access_args *))err_blkatoff
#define spec_valloc (int (*) (struct  vnop_access_args *))err_valloc
#define spec_vfree (int (*) (struct  vnop_access_args *))err_vfree
#define spec_bwrite (int (*) (struct  vnop_bwrite_args *))nop_bwrite
int     spec_blktooff (struct  vnop_blktooff_args *);
int     spec_offtoblk (struct  vnop_offtoblk_args *);
int     spec_blockmap (struct  vnop_blockmap_args *);

#endif /* _FUSE_VNOPS_H_ */
