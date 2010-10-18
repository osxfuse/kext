/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

/*
 * 'rebel' branch modifications:
 *     Copyright (C) Tuxera 2010. All Rights Reserved.
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_access, ap);
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
	locked_vnop(ap->a_vp, fuse_vnop_blktooff, ap);
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
	locked_vnop(ap->a_vp, fuse_vnop_blockmap, ap);
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
	/* Note: kpi_vfs.c does not take the node lock if vnode type is VCHR,
	 * VFIFO or VSOCK. I'm not sure if this is relevant here. */
	nodelocked_vnop(ap->a_vp, fuse_vnop_close, ap);
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
	nodelocked_vnop(ap->a_dvp, fuse_vnop_create, ap);
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
	nodelocked_pair_vnop(ap->a_fvp, ap->a_tvp, fuse_vnop_exchange, ap);
}

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
	nodelocked_vnop(ap->a_vp, fuse_vnop_fsync, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_getattr, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_getxattr, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_inactive, ap);
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
	/* Note: kpi_vfs.c does not take the node lock if vnode type is VCHR,
	 * VFIFO or VSOCK. I'm not sure if this is relevant here. */
	nodelocked_vnop(ap->a_vp, fuse_vnop_ioctl, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_kqfilt_add, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_kqfilt_remove, ap);
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
	/* TODO: What about a_tdvp? No need to lock that one? kpi_vfs.c does
	 * not, but maybe we should... */
	nodelocked_vnop(ap->a_vp, fuse_vnop_link, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_listxattr, ap);
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
	/* Note: kpi_vfs.c does not release the node lock if ap->a_cnp->cn_flags
	 * has the flags ISLASTCN and LOCKPARENT set, and if the flag
	 * FSNODELOCKHELD is not set. We only have access to the ISLASTCN and
	 * LOCKPARENT flags, so we can't do this but should we, and why? */
	nodelocked_vnop(ap->a_dvp, fuse_vnop_lookup, ap);
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
	nodelocked_vnop(ap->a_dvp, fuse_vnop_mkdir, ap);
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
	nodelocked_vnop(ap->a_dvp, fuse_vnop_mknod, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_mmap, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_mnomap, ap);
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
	locked_vnop(ap->a_vp, fuse_vnop_offtoblk, ap);
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
	/* Note: kpi_vfs.c does not take the node lock if vnode type is VCHR,
	 * VFIFO or VSOCK. I'm not sure if this is relevant here. */
	nodelocked_vnop(ap->a_vp, fuse_vnop_open, ap);
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
	locked_vnop(ap->a_vp, fuse_vnop_pagein, ap);
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
	locked_vnop(ap->a_vp, fuse_vnop_pageout, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_pathconf, ap);
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
	/* Note: kpi_vfs.c does not take the node lock if vnode type is VCHR,
	 * VFIFO or VSOCK. I'm not sure if this is relevant here. */
	nodelocked_vnop(ap->a_vp, fuse_vnop_read, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_readdir, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_readlink, ap);
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
	locked_vnop(ap->a_vp, fuse_vnop_reclaim, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_remove, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_removexattr, ap);
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
	/* Note: Do we really know that all vnodes are FUSE vnodes? I hope so,
	 * and it seems that HFS makes similar assumptions.
	 * Of course, how could we operate on vnodes that we don't know anything
	 * about? */
	nodelocked_quad_vnop(ap->a_tdvp, ap->a_fdvp, ap->a_fvp, ap->a_tvp,
		fuse_vnop_rename, ap);
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
	locked_vnop(ap->a_vp, fuse_vnop_revoke, ap);
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
	/* TODO: Shouldn't we also lock ap->a_dvp? kpi_vfs.c does not, but maybe
	 * we should anyway... */
	nodelocked_vnop(ap->a_vp, fuse_vnop_rmdir, ap);
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
	/* Note: kpi_vfs.c does not take the node lock if vnode type is VCHR,
	 * VFIFO or VSOCK. I'm not sure if this is relevant here. */
	nodelocked_vnop(ap->a_vp, fuse_vnop_select, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_setattr, ap);
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
	nodelocked_vnop(ap->a_vp, fuse_vnop_setxattr, ap);
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
	/* VNOP_STRATEGY in kpi_vfs.c is completely unprotected. This seems very
	 * dangerous, but I don't want to do anything that kpi_vfs.c doesn't do
	 * without being able to motivate why. */
	return fuse_vnop_strategy(ap);
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
	nodelocked_vnop(ap->a_dvp, fuse_vnop_symlink, ap);
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
	/* Note: kpi_vfs.c does not take the node lock if vnode type is VCHR,
	 * VFIFO or VSOCK. I'm not sure if this is relevant here. */
	nodelocked_vnop(ap->a_vp, fuse_vnop_write, ap);
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
