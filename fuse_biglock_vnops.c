/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#include <sys/param.h>
#include <kern/assert.h>
#include <libkern/libkern.h>
#include <libkern/OSMalloc.h>
#include <libkern/locks.h>
#include <mach/mach_types.h>
#include <sys/dirent.h>
#include <sys/disk.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/kernel_types.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/ubc.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/vnode_if.h>
#include <sys/xattr.h>
#include <sys/buf.h>
#include <sys/namei.h>
#include <sys/mman.h>
#include <vfs/vfs_support.h>

#include <fuse_param.h>

#include "fuse.h"
#include "fuse_kludges.h"
#include "fuse_locking.h"
#include "fuse_node.h"
#include "fuse_biglock_vnops.h"
#include "fuse_ipc.h"

#if M_MACFUSE_ENABLE_INTERIM_FSNODE_LOCK

#include "fuse_vnops.h"

/* Change this to 1 for extensive debug logging of method entry/exit. */
#define _DEBUG_LOGGING 0

#if _DEBUG_LOGGING
#define rawlog(msg, args...) IOLog(msg, ##args)

#define log(fmt, args...) \
	do { \
		rawlog(fmt, ##args); \
		rawlog("\n"); \
	} while(0)

#define log_enter(params_format, args...) \
	do { \
		rawlog("[%s:%d] Entering %s: ", __FILE__, __LINE__, __FUNCTION__); \
		log(params_format, ##args); \
	} while(0)

#define log_leave(return_format, args...) \
	do { \
		rawlog("[%s:%d] Leaving %s: ", __FILE__, __LINE__, __FUNCTION__); \
		log(return_format, ##args); \
	} while(0)
#else
#define log(fmt, args...) do {} while(0)
#define log_enter(params_format, args...) do {} while(0)
#define log_leave(return_format, args...) do {} while(0)
#endif /* _DEBUG_LOGGING */

#define fuse_biglock_lock(lock) \
	do { \
		log("%s: Aquiring biglock...", __FUNCTION__); \
		fusefs_recursive_lock_lock(lock); \
		log("%s:   biglock aquired!", __FUNCTION__); \
	} while(0)

#define fuse_biglock_unlock(lock) \
	do { \
		log("%s: Releasing biglock...", __FUNCTION__); \
		fusefs_recursive_lock_unlock(lock); \
		log("%s:   biglock released!", __FUNCTION__); \
	} while(0)

#define fuse_biglock_t fusefs_recursive_lock

/*
 struct vnop_access_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 int                  a_action;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_access(struct vnop_access_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_access(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_blktooff_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 daddr64_t            a_lblkno;
 off_t               *a_offset;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_blktooff(struct vnop_blktooff_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_blktooff(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_blockmap_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 off_t                a_foffset;
 size_t               a_size;
 daddr64_t           *a_bpn;
 size_t              *a_run;
 void                *a_poff;
 int                  a_flags;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_blockmap(struct vnop_blockmap_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_blockmap(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_close_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 int                  a_fflag;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_close(struct vnop_close_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_close(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_create_args {
 struct vnodeop_desc  *a_desc;
 vnode_t               a_dvp;
 vnode_t              *a_vpp;
 struct componentname *a_cnp;
 struct vnode_attr    *a_vap;
 vfs_context_t         a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_create(struct vnop_create_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_dvp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_create(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_exchange_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_fvp;
 vnode_t              a_tvp;
 int                  a_options;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_exchange(struct vnop_exchange_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_fvp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_exchange(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 * Our vnop_fsync roughly corresponds to the FUSE_FSYNC method. The Linux
 * version of FUSE also has a FUSE_FLUSH method.
 *
 * On Linux, fsync() synchronizes a file's complete in-core state with that
 * on disk. The call is not supposed to return until the system has completed
 * that action or until an error is detected.
 *
 * Linux also has an fdatasync() call that is similar to fsync() but is not
 * required to update the metadata such as access time and modification time.
 */

/*
 struct vnop_fsync_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 int                  a_waitfor;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_fsync(struct vnop_fsync_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_fsync(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_getattr_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 struct vnode_attr   *a_vap;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_getattr(struct vnop_getattr_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_getattr(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

#if M_MACFUSE_ENABLE_XATTR
/*
 struct vnop_getxattr_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 char                *a_name;
 uio_t                a_uio;
 size_t              *a_size;
 int                  a_options;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_getxattr(struct vnop_getxattr_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_getxattr(ap);
	fuse_biglock_unlock(biglock);
	return res;
}
#endif /* M_MACFUSE_ENABLE_XATTR */

/*
 struct vnop_inactive_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_inactive(struct vnop_inactive_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_inactive(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_ioctl_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 u_long               a_command;
 caddr_t              a_data;
 int                  a_fflag;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_ioctl(struct vnop_ioctl_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_ioctl(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

#if M_MACFUSE_ENABLE_KQUEUE

/*
 struct vnop_kqfilt_add_args {
 struct vnodeop_desc  *a_desc;
 vnode_t               a_vp;
 struct knote         *a_kn;
 struct proc          *p;
 vfs_context_t         a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_kqfilt_add(struct vnop_kqfilt_add_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_kqfilt_add(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_kqfilt_remove_args {
 struct vnodeop_desc  *a_desc;
 vnode_t               a_vp;
 uintptr_t             ident;
 vfs_context_t         a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_kqfilt_remove(struct vnop_kqfilt_remove_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_kqfilt_remove(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

#endif /* M_MACFUSE_ENABLE_KQUEUE */

/*
 struct vnop_link_args {
 struct vnodeop_desc  *a_desc;
 vnode_t               a_vp;
 vnode_t               a_tdvp;
 struct componentname *a_cnp;
 vfs_context_t         a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_link(struct vnop_link_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_link(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

#if M_MACFUSE_ENABLE_XATTR
/*
 struct vnop_listxattr_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 uio_t                a_uio;
 size_t              *a_size;
 int                  a_options;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_listxattr(struct vnop_listxattr_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_listxattr(ap);
	fuse_biglock_unlock(biglock);
	return res;
}
#endif /* M_MACFUSE_ENABLE_XATTR */

/*
 struct vnop_lookup_args {
 struct vnodeop_desc  *a_desc;
 vnode_t               a_dvp;
 vnode_t              *a_vpp;
 struct componentname *a_cnp;
 vfs_context_t         a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_lookup(struct vnop_lookup_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_dvp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_lookup(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_mkdir_args {
 struct vnodeop_desc  *a_desc;
 vnode_t               a_dvp;
 vnode_t              *a_vpp;
 struct componentname *a_cnp;
 struct vnode_attr    *a_vap;
 vfs_context_t         a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_mkdir(struct vnop_mkdir_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_dvp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_mkdir(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_mknod_args {
 struct vnodeop_desc  *a_desc;
 vnode_t               a_dvp;
 vnode_t              *a_vpp;
 struct componentname *a_cnp;
 struct vnode_attr    *a_vap;
 vfs_context_t         a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_mknod(struct vnop_mknod_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_dvp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_mknod(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_mmap_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 int                  a_fflags;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_mmap(struct vnop_mmap_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_mmap(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_mnomap_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_mnomap(struct vnop_mnomap_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_mnomap(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_offtoblk_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 off_t                a_offset;
 daddr64_t           *a_lblkno;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_offtoblk(struct vnop_offtoblk_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_offtoblk(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_open_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 int                  a_mode;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_open(struct vnop_open_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_open(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_pagein_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 upl_t                a_pl;
 vm_offset_t          a_pl_offset;
 off_t                a_f_offset;
 size_t               a_size;
 int                  a_flags;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_pagein(struct vnop_pagein_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_pagein(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_pageout_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 upl_t                a_pl;
 vm_offset_t          a_pl_offset;
 off_t                a_f_offset;
 size_t               a_size;
 int                  a_flags;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_pageout(struct vnop_pageout_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_pageout(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_pathconf_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 int                  a_name;
 int                 *a_retval;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_pathconf(struct vnop_pathconf_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_pathconf(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_read_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 struct uio          *a_uio;
 int                  a_ioflag;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_read(struct vnop_read_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_read(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_readdir_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 struct uio          *a_uio;
 int                  a_flags;
 int                 *a_eofflag;
 int                 *a_numdirent;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_readdir(struct vnop_readdir_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_readdir(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_readlink_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 struct uio          *a_uio;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_readlink(struct vnop_readlink_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_readlink(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_reclaim_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_reclaim(struct vnop_reclaim_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_reclaim(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_remove_args {
 struct vnodeop_desc  *a_desc;
 vnode_t               a_dvp;
 vnode_t               a_vp;
 struct componentname *a_cnp;
 int                   a_flags;
 vfs_context_t         a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_remove(struct vnop_remove_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_remove(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

#if M_MACFUSE_ENABLE_XATTR
/*
 struct vnop_removexattr_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 char                *a_name;
 int                  a_options;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_removexattr(struct vnop_removexattr_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_removexattr(ap);
	fuse_biglock_unlock(biglock);
	return res;
}
#endif /* M_MACFUSE_ENABLE_XATTR */

/*
 struct vnop_rename_args {
 struct vnodeop_desc  *a_desc;
 vnode_t               a_fdvp;
 vnode_t               a_fvp;
 struct componentname *a_fcnp;
 vnode_t               a_tdvp;
 vnode_t               a_tvp;
 struct componentname *a_tcnp;
 vfs_context_t         a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_rename(struct vnop_rename_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_fvp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_rename(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 *  struct vnop_revoke_args {
 *      struct vnodeop_desc  *a_desc;
 *      vnode_t               a_vp;
 *      int                   a_flags;
 *      vfs_context_t         a_context;
 *  };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_revoke(struct vnop_revoke_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_revoke(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_rmdir_args {
 struct vnodeop_desc  *a_desc;
 vnode_t               a_dvp;
 vnode_t               a_vp;
 struct componentname *a_cnp;
 vfs_context_t         a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_rmdir(struct vnop_rmdir_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_rmdir(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_select_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 int                  a_which;
 int                  a_fflags;
 void                *a_wql;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_select(__unused struct vnop_select_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_select(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_setattr_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 struct vnode_attr   *a_vap;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_setattr(struct vnop_setattr_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_setattr(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

#if M_MACFUSE_ENABLE_XATTR
/*
 struct vnop_setxattr_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 char                *a_name;
 uio_t                a_uio;
 int                  a_options;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_setxattr(struct vnop_setxattr_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_setxattr(ap);
	fuse_biglock_unlock(biglock);
	return res;
}
#endif /* M_MACFUSE_ENABLE_XATTR */

/*
 struct vnop_strategy_args {
 struct vnodeop_desc *a_desc;
 struct buf          *a_bp;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_strategy(struct vnop_strategy_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(buf_vnode(ap->a_bp)))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_strategy(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_symlink_args {
 struct vnodeop_desc  *a_desc;
 vnode_t               a_dvp;
 vnode_t              *a_vpp;
 struct componentname *a_cnp;
 struct vnode_attr    *a_vap;
 char                 *a_target;
 vfs_context_t         a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_symlink(struct vnop_symlink_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_dvp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_symlink(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

/*
 struct vnop_write_args {
 struct vnodeop_desc *a_desc;
 vnode_t              a_vp;
 struct uio          *a_uio;
 int                  a_ioflag;
 vfs_context_t        a_context;
 };
 */
FUSE_VNOP_EXPORT
int
fuse_biglock_vnop_write(struct vnop_write_args *ap)
{
	int res;
	fuse_biglock_t *biglock = fuse_get_mpdata(vnode_mount(ap->a_vp))->biglock;
	fuse_biglock_lock(biglock);
	res = fuse_vnop_write(ap);
	fuse_biglock_unlock(biglock);
	return res;
}

struct vnodeopv_entry_desc fuse_biglock_vnode_operation_entries[] = {
    { &vnop_access_desc,        (fuse_vnode_op_t) fuse_biglock_vnop_access        },
    { &vnop_advlock_desc,       (fuse_vnode_op_t) err_advlock             },
	//  { &vnop_allocate_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_allocate      },
    { &vnop_blktooff_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_blktooff      },
    { &vnop_blockmap_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_blockmap      },
	//  { &vnop_bwrite_desc,        (fuse_vnode_op_t) fuse_biglock_vnop_bwrite        },
    { &vnop_close_desc,         (fuse_vnode_op_t) fuse_biglock_vnop_close         },
	//  { &vnop_copyfile_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_copyfile      },
    { &vnop_create_desc,        (fuse_vnode_op_t) fuse_biglock_vnop_create        },
    { &vnop_default_desc,       (fuse_vnode_op_t) vn_default_error        },
    { &vnop_exchange_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_exchange      },
    { &vnop_fsync_desc,         (fuse_vnode_op_t) fuse_biglock_vnop_fsync         },
    { &vnop_getattr_desc,       (fuse_vnode_op_t) fuse_biglock_vnop_getattr       },
	//  { &vnop_getattrlist_desc,   (fuse_vnode_op_t) fuse_biglock_vnop_getattrlist   },
#if M_MACFUSE_ENABLE_XATTR
    { &vnop_getxattr_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_getxattr      },
#endif /* M_MACFUSE_ENABLE_XATTR */
    { &vnop_inactive_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_inactive      },
    { &vnop_ioctl_desc,         (fuse_vnode_op_t) fuse_biglock_vnop_ioctl         },
    { &vnop_link_desc,          (fuse_vnode_op_t) fuse_biglock_vnop_link          },
#if M_MACFUSE_ENABLE_XATTR
    { &vnop_listxattr_desc,     (fuse_vnode_op_t) fuse_biglock_vnop_listxattr     },
#endif /* M_MACFUSE_ENABLE_XATTR */
    { &vnop_lookup_desc,        (fuse_vnode_op_t) fuse_biglock_vnop_lookup        },
#if M_MACFUSE_ENABLE_KQUEUE
    { &vnop_kqfilt_add_desc,    (fuse_vnode_op_t) fuse_biglock_vnop_kqfilt_add    },
    { &vnop_kqfilt_remove_desc, (fuse_vnode_op_t) fuse_biglock_vnop_kqfilt_remove },
#endif /* M_MACFUSE_ENABLE_KQUEUE */
    { &vnop_mkdir_desc,         (fuse_vnode_op_t) fuse_biglock_vnop_mkdir         },
    { &vnop_mknod_desc,         (fuse_vnode_op_t) fuse_biglock_vnop_mknod         },
    { &vnop_mmap_desc,          (fuse_vnode_op_t) fuse_biglock_vnop_mmap          },
    { &vnop_mnomap_desc,        (fuse_vnode_op_t) fuse_biglock_vnop_mnomap        },
    { &vnop_offtoblk_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_offtoblk      },
    { &vnop_open_desc,          (fuse_vnode_op_t) fuse_biglock_vnop_open          },
    { &vnop_pagein_desc,        (fuse_vnode_op_t) fuse_biglock_vnop_pagein        },
    { &vnop_pageout_desc,       (fuse_vnode_op_t) fuse_biglock_vnop_pageout       },
    { &vnop_pathconf_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_pathconf      },
    { &vnop_read_desc,          (fuse_vnode_op_t) fuse_biglock_vnop_read          },
    { &vnop_readdir_desc,       (fuse_vnode_op_t) fuse_biglock_vnop_readdir       },
	//  { &vnop_readdirattr_desc,   (fuse_vnode_op_t) fuse_biglock_vnop_readdirattr   },
    { &vnop_readlink_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_readlink      },
    { &vnop_reclaim_desc,       (fuse_vnode_op_t) fuse_biglock_vnop_reclaim       },
    { &vnop_remove_desc,        (fuse_vnode_op_t) fuse_biglock_vnop_remove        },
#if M_MACFUSE_ENABLE_XATTR
    { &vnop_removexattr_desc,   (fuse_vnode_op_t) fuse_biglock_vnop_removexattr   },
#endif /* M_MACFUSE_ENABLE_XATTR */
    { &vnop_rename_desc,        (fuse_vnode_op_t) fuse_biglock_vnop_rename        },
    { &vnop_revoke_desc,        (fuse_vnode_op_t) fuse_biglock_vnop_revoke        },
    { &vnop_rmdir_desc,         (fuse_vnode_op_t) fuse_biglock_vnop_rmdir         },
	//  { &vnop_searchfs_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_searchfs      },
    { &vnop_select_desc,        (fuse_vnode_op_t) fuse_biglock_vnop_select        },
    { &vnop_setattr_desc,       (fuse_vnode_op_t) fuse_biglock_vnop_setattr       },
	//  { &vnop_setattrlist_desc,   (fuse_vnode_op_t) fuse_biglock_vnop_setattrlist   },
#if M_MACFUSE_ENABLE_XATTR
    { &vnop_setxattr_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_setxattr      },
#endif /* M_MACFUSE_ENABLE_XATTR */
    { &vnop_strategy_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_strategy      },
    { &vnop_symlink_desc,       (fuse_vnode_op_t) fuse_biglock_vnop_symlink       },
	//  { &vnop_whiteout_desc,      (fuse_vnode_op_t) fuse_biglock_vnop_whiteout      },
    { &vnop_write_desc,         (fuse_vnode_op_t) fuse_biglock_vnop_write         },
    { NULL, NULL }
};

#endif /* M_MACFUSE_ENABLE_INTERIM_FSNODE_LOCK */
