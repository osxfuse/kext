/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2010 Tuxera Inc.
 * Copyright (c) 2011-2012 Anatol Pomozov
 * Copyright (c) 2011-2017 Benjamin Fleischer
 * All rights reserved.
 */

#include "fuse_vnops.h"

#include "fuse_file.h"
#include "fuse_internal.h"
#include "fuse_ipc.h"
#include "fuse_node.h"
#include "fuse_nodehash.h"

#if M_OSXFUSE_ENABLE_BIG_LOCK
#  include "fuse_biglock_vnops.h"
#endif

#include <fuse_ioctl.h>

#include <sys/namei.h>

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
fuse_vnop_access(struct vnop_access_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    int           action  = ap->a_action;
    vfs_context_t context = ap->a_context;

    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        if (vnode_isvroot(vp)) {
            return 0;
        } else {
            return ENXIO;
        }
    }

    if (!(data->dataflags & FSESS_INITED)) {
        if (vnode_isvroot(vp)) {
            if (fuse_vfs_context_issuser(context) ||
               (fuse_match_cred(data->daemoncred,
                                vfs_context_ucred(context)) == 0)) {
                return 0;
            }
        }
        return EBADF;
    }

    if (vnode_islnk(vp)) {
        return 0;
    }

    return fuse_internal_access(vp, action, context);
}

/*
    struct vnop_allocate_args {
	    struct vnodeop_desc *a_desc;
	    vnode_t              a_vp;
	    off_t                a_length;
	    u_int32_t            a_flags;
	    off_t               *a_bytesallocated;
	    off_t                a_offset;
	    vfs_context_t        a_context;
    };
*/
FUSE_VNOP_EXPORT
int
fuse_vnop_allocate(struct vnop_allocate_args *ap)
{
    vnode_t        vp             = ap->a_vp;
    off_t          length         = ap->a_length;
    u_int32_t      flags          = ap->a_flags;
    off_t         *bytesallocated = ap->a_bytesallocated;
    off_t          offset         = ap->a_offset;
    vfs_context_t  context        = ap->a_context;

    struct fuse_filehandle   *fufh = NULL;
    fufh_type_t               fufh_type = FUFH_WRONLY;
    struct fuse_vnode_data   *fvdat = VTOFUD(vp);
    struct fuse_dispatcher    fdi;
    struct fuse_abi_data      ffai;
    struct fuse_data         *data = fuse_get_mpdata(vnode_mount(vp));

    int err = 0;
    uint32_t mode = 0;

    fuse_trace_printf_vnop();

    *bytesallocated = 0;

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    if (!fuse_implemented(data, FSESS_NOIMPLBIT(FALLOCATE))) {
        return ENOTSUP;
    }

    if (!vnode_isreg(vp)) {
        return EISDIR;
    }
	if (length < (off_t)0) {
        return EINVAL;
    }

    if ((flags & ALLOCATEFROMVOL) && (length < fvdat->filesize)) {
		/* See hfs_vnop_allocate */
        return EINVAL;
	}

    fufh = &(fvdat->fufh[fufh_type]);
    if (!FUFH_IS_VALID(fufh)) {
        fufh_type = FUFH_RDWR;
        fufh = &(fvdat->fufh[fufh_type]);
        if (!FUFH_IS_VALID(fufh)) {
            fufh = NULL;
        } else {
            /* Falling back to FUFH_RDWR. */
        }
    }

    if (!fufh) {
        /* Failing allocate because of no fufh. */
        return EIO;
    } else {
        /* Using existing fufh of type fufh_type. */
    }

    mode = flags;
    if (flags & PREALLOCATE) {
        /*
         * Note: FUSE_FALLOCATE does not return the actual number of bytes that
         * have been allocated. Therefore we set the ALLOCATEALL flag (allocate
         * all requested space or no space at all) and return a_length in case
         * FUSE_FALLOCATE succeeds.
         */
        mode |= ALLOCATEALL;
    }

    fdisp_init_abi(&fdi, fuse_fallocate_in, data);
    fdisp_make_vp(&fdi, FUSE_FALLOCATE, vp, context);
    fuse_abi_data_init(&ffai, DATOI(data), fdi.indata);

    fuse_fallocate_in_set_fh(&ffai, fufh->fh_id);
    fuse_fallocate_in_set_offset(&ffai, (uint64_t)offset);
    fuse_fallocate_in_set_length(&ffai, (uint64_t)length);
    fuse_fallocate_in_set_mode(&ffai, mode);

    err = fdisp_wait_answ(&fdi);
    if (err) {
        if (err == ENOSYS) {
            /* Make sure we don't come in here again. */
            fuse_clear_implemented(data, FSESS_NOIMPLBIT(FALLOCATE));
            err = ENOTSUP;
        }
    } else {
        fuse_ticket_release(fdi.tick);

        if (flags & ALLOCATEFROMVOL) {
            *bytesallocated = length - fvdat->filesize;
        } else {
            *bytesallocated = length;
        }
    }

    return err;
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
fuse_vnop_blktooff(struct vnop_blktooff_args *ap)
{
    vnode_t    vp        = ap->a_vp;
    daddr64_t  lblkno    = ap->a_lblkno;
    off_t     *offsetPtr = ap->a_offset;

    struct fuse_data *data;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    data = fuse_get_mpdata(vnode_mount(vp));

    *offsetPtr = lblkno * (off_t)(data->blocksize);

    return 0;
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
fuse_vnop_blockmap(struct vnop_blockmap_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    off_t         foffset = ap->a_foffset;
    size_t        size    = ap->a_size;
    daddr64_t    *bpnPtr  = ap->a_bpn;
    size_t       *runPtr  = ap->a_run;
    int          *poffPtr = (int *)ap->a_poff;

    /* Ignoring flags and context */

    struct fuse_vnode_data *fvdat;
    struct fuse_data       *data;

    off_t contiguousPhysicalBytes;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    if (vnode_isdir(vp)) {
        return ENOTSUP;
    }

    if (ap->a_bpn == NULL) {
        return 0;
    }

    fvdat = VTOFUD(vp);
    data = fuse_get_mpdata(vnode_mount(vp));

    /*
     * We could assert that:
     *
     * (foffset % data->blocksize) == 0
     * (foffset < fvdat->filesize)
     * (size % data->blocksize) == 0)
     */

    *bpnPtr = foffset / data->blocksize;

    contiguousPhysicalBytes = \
        fvdat->filesize - (off_t)(*bpnPtr * data->blocksize);

    /* contiguousPhysicalBytes cannot really be negative (could assert) */

    if (contiguousPhysicalBytes > (off_t)size) {
        contiguousPhysicalBytes = (off_t)size;
    }

    if (runPtr != NULL) {
        *runPtr = (size_t)contiguousPhysicalBytes;
    }

    if (poffPtr != NULL) {
        *poffPtr = 0;
    }

    return 0;
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
fuse_vnop_close(struct vnop_close_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    int           fflag   = ap->a_fflag;
    vfs_context_t context = ap->a_context;

    int err   = 0;
    int isdir = (vnode_isdir(vp)) ? 1 : 0;

    fufh_type_t fufh_type;
    struct fuse_data *data;

    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh  = NULL;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return 0;
    }

    /* vclean() calls VNOP_CLOSE with fflag set to IO_NDELAY. */
    if (fflag == IO_NDELAY) {
        return 0;
    }

    if (isdir) {
        fufh_type = FUFH_RDONLY;
    } else {
        fufh_type = fuse_filehandle_xlate_from_fflags(fflag);
    }

    fufh = &(fvdat->fufh[fufh_type]);

    if (!FUFH_IS_VALID(fufh)) {
        IOLog("osxfuse: fufh invalid in close [type=%d oc=%d vtype=%d cf=%d]\n",
              fufh_type, fufh->open_count, vnode_vtype(vp), fflag);
        return 0;
    }

    if (isdir) {
        goto skipdir;
    }

    data = fuse_get_mpdata(vnode_mount(vp));

    /*
     * Enforce sync-on-close unless explicitly told not to.
     *
     * We do this to maintain correct semantics in the not so common case when
     * you create a file with O_RDWR but without write permissions--you /are/
     * supposed to be able to write to such a file given the descriptor you
     * you got from open()/create(). Therefore, if we don't finish all our
     * writing before we close this precious writable descriptor, we might
     * be doomed.
     */
    if (vnode_hasdirtyblks(vp) && !fuse_isnosynconclose(vp)) {
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_unlock(data->biglock);
#endif
        (void)cluster_push(vp, IO_SYNC | IO_CLOSE);
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_lock(data->biglock);
#endif
    }

    if (fuse_implemented(data, FSESS_NOIMPLBIT(FLUSH))) {

        struct fuse_dispatcher fdi;
        struct fuse_abi_data   ffi;

        fdisp_init_abi(&fdi, fuse_flush_in, data);
        fdisp_make_vp(&fdi, FUSE_FLUSH, vp, context);
        fuse_abi_data_init(&ffi, DATOI(data), fdi.indata);

        fuse_flush_in_set_fh(&ffi, fufh->fh_id);
        fuse_flush_in_set_lock_owner(&ffi, 0);

        err = fdisp_wait_answ(&fdi);
        if (!err) {
            fuse_ticket_release(fdi.tick);
        } else if (err == ENOSYS) {
            fuse_clear_implemented(data, FSESS_NOIMPLBIT(FLUSH));
            err = 0;
        }
    }

skipdir:

    /* This must be done after we have flushed any pending I/O. */
    FUFH_USE_DEC(fufh);

    if (!FUFH_IS_VALID(fufh)) {
        (void)fuse_filehandle_put(vp, context, fufh_type, FUSE_OP_FOREGROUNDED);
    }

    return err;
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
fuse_vnop_create(struct vnop_create_args *ap)
{
    vnode_t               dvp     = ap->a_dvp;
    vnode_t              *vpp     = ap->a_vpp;
    struct componentname *cnp     = ap->a_cnp;
    struct vnode_attr    *vap     = ap->a_vap;
    vfs_context_t         context = ap->a_context;

    struct fuse_abi_data    fci;
    struct fuse_mknod_in    fmni_data;
    struct fuse_abi_data    fmni;
    struct fuse_abi_data    feo;
    struct fuse_dispatcher  fdi;
    struct fuse_dispatcher *fdip = &fdi;

    uint32_t flags;
    int err;
    bool gone_good_old = false;
    void *next;

    struct fuse_data *data;

    mount_t mp = vnode_mount(dvp);
    uint64_t parent_nodeid = VTOFUD(dvp)->nodeid;
    mode_t mode = MAKEIMODE(vap->va_type, vap->va_mode);

    fuse_trace_printf_vnop_novp();

    if (fuse_isdeadfs_fs(dvp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(dvp, context, EPERM);

    if (fuse_skip_apple_double_mp(mp, cnp->cn_nameptr, cnp->cn_namelen)) {
        return EPERM;
    }

    data = fuse_get_mpdata(mp);

    fdata_wait_init(data);
    fdisp_init(fdip, 0);

    if (!fuse_implemented(data, FSESS_NOIMPLBIT(CREATE)) ||
        (vap->va_type != VREG)) {

        /* User-space file system does not implement CREATE */

        goto good_old;
    }

    fdi.iosize = fuse_create_in_sizeof(DATOI(data)) +
                 cnp->cn_namelen + 1;
    fdisp_make(fdip, FUSE_CREATE, vnode_mount(dvp), parent_nodeid, context);
    fuse_abi_data_init(&fci, DATOI(data), fdip->indata);

    /* We always create files like this. Wish we were on Linux. */
    flags = O_CREAT | O_RDWR;

    if (!(data->dataflags & FSESS_EXCL_CREATE)
        || vap->va_vaflags & VA_EXCLUSIVE) {
        /*
         * Note: The kernel expects creat to return EEXIST in case the file
         * already exists. If FSESS_EXCL_CREATE is set, O_EXCL will only be set
         * for "truly" exclusive create calls. This allows network file systems
         * to determine whether or not to acquire a potentially costly lock to
         * prevent remote create races.
         */
        flags |= O_EXCL;
    }

    if (cnp->cn_nameptr && cnp->cn_namelen > 2
        && cnp->cn_nameptr[0] == '.' && cnp->cn_nameptr[1] == '_') {
        /*
         * Note: The kernel's fallback mechanism for managing extended
         * attributes is not thread-safe. Creating Apple Double files with
         * O_EXCL set might result in setxattr(2) failing.
         */
        flags &= ~O_EXCL;
    }

    fuse_create_in_set_flags(&fci, flags);
    fuse_create_in_set_mode(&fci, mode);
    fuse_create_in_set_umask(&fci, 0);

    next = (char *)fdip->indata + fuse_create_in_sizeof(DATOI(data));

    memcpy(next, cnp->cn_nameptr, cnp->cn_namelen);
    ((char *)next)[cnp->cn_namelen] = '\0';

    err = fdisp_wait_answ(fdip);

    if (err == ENOSYS) {
        fuse_clear_implemented(data, FSESS_NOIMPLBIT(CREATE));
        goto good_old;
    } else if (err) {
        goto undo;
    }

    goto bringup;

good_old:
    gone_good_old = true;

    fuse_abi_data_init(&fmni, DATOI(data), &fmni_data);

    fuse_mknod_in_set_mode(&fmni, mode); /* fvdat->flags; */
    fuse_mknod_in_set_rdev(&fmni, 0);
    fuse_mknod_in_set_umask(&fmni, 0);

    fuse_internal_newentry_makerequest(vnode_mount(dvp), parent_nodeid, cnp,
                                       FUSE_MKNOD, fmni.fad_data,
                                       fuse_mknod_in_sizeof(DATOI(data)),
                                       fdip, context);
    err = fdisp_wait_answ(fdip);
    if (err) {
        goto undo;
    }

bringup:
    fuse_abi_data_init(&feo, DATOI(data), fdip->answ);
    next = (char *)fdip->answ + fuse_entry_out_sizeof(DATOI(data));

    err = fuse_internal_checkentry(&feo, VREG);
    if (err) { // VBLK/VCHR not allowed
        fuse_ticket_release(fdip->tick);
        goto undo;
    }

    err = fuse_vget_i(vpp, (gone_good_old) ? 0 : FN_CREATING, &feo, cnp, dvp,
                      mp, context);
    if (err) {
        if (gone_good_old) {
            fuse_internal_forget_send(mp, context, fuse_entry_out_get_nodeid(&feo), 1, fdip);
        } else {
            struct fuse_abi_data foo;
            struct fuse_abi_data fri;

            fuse_abi_data_init(&foo, DATOI(data), next);

            fdip->iosize = fuse_release_in_sizeof(DATOI(data));
            fdisp_make(fdip, FUSE_RELEASE, mp, fuse_entry_out_get_nodeid(&feo), context);
            fuse_abi_data_init(&fri, DATOI(data), fdip->indata);

            fuse_release_in_set_fh(&fri, fuse_open_out_get_fh(&foo));
            fuse_release_in_set_flags(&fri, OFLAGS(mode));

            fuse_insert_callback(fdip->tick, fuse_internal_forget_callback);
            fuse_insert_message(fdip->tick);
        }
        fuse_ticket_release(fdip->tick);
        return err;
    }

    if (!gone_good_old) {
        struct fuse_vnode_data *fvdat = VTOFUD(*vpp);
        struct fuse_filehandle *fufh = &(fvdat->fufh[FUFH_RDWR]);

        struct fuse_abi_data foo;

        fuse_abi_data_init(&foo, DATOI(data), next);

        fufh->fh_id = fuse_open_out_get_fh(&foo);
        fufh->open_flags = fuse_open_out_get_open_flags(&foo);

        /*
         * We're stashing this to be picked up by open. Meanwhile, we set
         * the use count to 1 because that's what it is. The use count will
         * later transfer to the slot that this handle ends up falling in.
         */
        fufh->open_count = 1;

        FUSE_OSAddAtomic(1, (SInt32 *)&fuse_fh_current);
    }

    fuse_invalidate_attr(dvp);
    cache_purge_negatives(dvp);

    fuse_ticket_release(fdip->tick);

    return 0;

undo:
    return err;
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
fuse_vnop_exchange(struct vnop_exchange_args *ap)
{

#if M_OSXFUSE_ENABLE_EXCHANGE

    vnode_t       fvp     = ap->a_fvp;
    vnode_t       tvp     = ap->a_tvp;
    int           options = ap->a_options;
    vfs_context_t context = ap->a_context;

    const char *fname = NULL;
    const char *tname = NULL;
    size_t flen = 0;
    size_t tlen = 0;

    struct fuse_data *data = fuse_get_mpdata(vnode_mount(fvp));

    int err = 0;

    fuse_trace_printf_vnop_novp();

    if (vnode_mount(fvp) != vnode_mount(tvp)) {
        return EXDEV;
    }

    /* We now know f and t are on the same volume. */

    if (!fuse_implemented(data, FSESS_NOIMPLBIT(EXCHANGE))) {
        return ENOTSUP;
    }

    if (fuse_isnovncache(fvp)) {
        return ENOTSUP;
    }

    if (fvp == tvp) {
        return EINVAL;
    }

    if (!vnode_isreg(fvp) || !vnode_isreg(tvp)) {
        return EINVAL;
    }

    if (fuse_isdeadfs_fs(fvp)) {
        return ENXIO;
    }

    fname = vnode_getname(fvp);
    if (!fname) {
        return EIO;
    }

    tname = vnode_getname(tvp);
    if (!tname) {
        vnode_putname(fname);
        return EIO;
    }

    flen = strlen(fname);
    tlen = strlen(tname);

    if ((flen > 2) && (*fname == '.') && (*(fname + 1) == '_')) {
        err = EINVAL;
        goto out;
    }

    if ((tlen > 2) && (*tname == '.') && (*(tname + 1) == '_')) {
        err = EINVAL;
        goto out;
    }

    err = fuse_internal_exchange(fvp, fname, flen, tvp, tname, tlen, options,
                                 context);

    if (err == ENOSYS) {
        fuse_clear_implemented(data, FSESS_NOIMPLBIT(EXCHANGE));
        err = ENOTSUP;
    }

out:

    vnode_putname(fname);
    vnode_putname(tname);

    return err;

#else /* !M_OSXFUSE_ENABLE_EXCHANGE */

    (void)ap;

    return ENOTSUP;

#endif /* M_OSXFUSE_ENABLE_EXCHANGE */

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
fuse_vnop_fsync(struct vnop_fsync_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    int           waitfor = ap->a_waitfor;
    vfs_context_t context = ap->a_context;

    (void)waitfor;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return 0;
    }

    return fuse_internal_fsync_vp(vp, context);
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
fuse_vnop_getattr(struct vnop_getattr_args *ap)
{
    vnode_t            vp      = ap->a_vp;
    struct vnode_attr *vap     = ap->a_vap;
    vfs_context_t      context = ap->a_context;

    struct timespec uptsp;
    struct fuse_dispatcher  fdi;
    struct fuse_data       *data;
    struct fuse_abi_data    fao;
    struct fuse_abi_data    fa;
    struct fuse_abi_data    fgi;
    struct fuse_vnode_data *fvdat;

    int err = 0;
    int dataflags;

    data = fuse_get_mpdata(vnode_mount(vp));

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        if (vnode_isvroot(vp)) {
            goto fake;
        } else {
            return ENXIO;
        }
    }

    if (fuse_vfs_context_issuser(context)) {
        /*
         * Note: Starting with OS X 10.11 DesktopServicesHelper (which is
         * running as root) calls stat(2) on behalf of Finder when trying to
         * delete a directory. Returning ENOENT results in Finder aborting the
         * delete process. Therefore we are no longer blocking calls by root
         * even if allow_root or allow_other is not set.
         */
    } else {
        CHECK_BLANKET_DENIAL(vp, context, ENOENT);
    }

    fvdat = VTOFUD(vp);
    dataflags = data->dataflags;

    /*
     * Note: We are not bailing out on a dead file system just yet
     */

    /* Look for cached attributes. */
    nanouptime(&uptsp);
    if (fuse_timespec_cmp(&uptsp, &fvdat->attr_valid, <=)) {
        if (vap != VTOVA(vp)) {
            fuse_internal_attr_loadvap(vp, vap, context);
        }
        return 0;
    }

    if (!(dataflags & FSESS_INITED) && !vnode_isvroot(vp)) {
        fdata_set_dead(data, false);
        err = ENOTCONN;
        return err;
    }

    /*
     * If we got here due to a fstat(2) call on an open-remotely-moved file on
     * a shared file system, the FUSE user space daemon would not be able to
     * locate that file by name and fstat(2) would fail. But if we passed an
     * open file handle and FGETATTR was implemented by the daemon, the call
     * might succeed.
     *
     * But by doing so, we would not get an ENOENT error in case the file does
     * no longer exist (under its original name) for as long as its vnode is in
     * the vnode name cache.
     */

    struct fuse_filehandle *fufh = NULL;
    int type;
    bool found_valid_fh = false;
    for (type = 0; type < FUFH_MAXTYPE; type++) {
        fufh = &(fvdat->fufh[type]);
        if (FUFH_IS_VALID(fufh)) {
            found_valid_fh = true;
            break;
        }
    }

    fdata_wait_init(data);
    fdisp_init_abi(&fdi, fuse_getattr_in, data);
    fdisp_make_vp(&fdi, FUSE_GETATTR, vp, context);
    fuse_abi_data_init(&fgi, DATOI(data), fdi.indata);

    if (found_valid_fh) {
        fuse_getattr_in_set_fh(&fgi, fufh->fh_id);
        fuse_getattr_in_set_getattr_flags(&fgi, FUSE_GETATTR_FH);
    } else {
        fuse_getattr_in_set_fh(&fgi, 0);
        fuse_getattr_in_set_getattr_flags(&fgi, 0);
    }

    err = fdisp_wait_answ(&fdi);
    if (err) {
        if ((err == ENOTCONN) && vnode_isvroot(vp)) {
            /* see comment at similar place in fuse_statfs() */
            goto fake;
        }
        if (err == ENOENT) {
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(data->biglock);
#endif
            fuse_internal_vnode_disappear(vp, context, REVOKE_SOFT);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(data->biglock);
#endif
        }
        return err;
    }

    fuse_abi_data_init(&fao, DATOI(data), fdi.answ);
    fuse_abi_data_init(&fa, fao.fad_version, fuse_attr_out_get_attr(&fao));

    /* XXX: Could check the sanity/volatility of va_mode here. */

    if ((fuse_attr_get_mode(&fa) & S_IFMT) == 0) {
        fuse_ticket_release(fdi.tick);
        return EIO;
    }

    cache_attrs(vp, fuse_attr_out, &fao);

    fvdat->c_flag &= ~C_XTIMES_VALID;

    fuse_internal_attr_loadvap(vp, vap, context);

#if M_OSXFUSE_EXPERIMENTAL_JUNK
    if (vap != VTOVA(vp)) {
        memcpy(vap, VTOVA(vp), sizeof(*vap));
    }
#endif

    /* ATTR_FUDGE_CASE */
    if (vnode_isreg(vp) && fuse_isnoubc(vp)) {
        /*
         * This is for those cases when the file size changed without us
         * knowing, and we want to catch up.
         *
         * For the sake of sanity, we don't want to do it with UBC.
         * We also don't want to do it when we have asynchronous writes
         * enabled because we might have pending writes on *our* side.
         * We're not researching distributed file systems here!
         */

        off_t new_filesize = fuse_attr_get_size(&fa);
        fvdat->filesize = new_filesize;
    }

    fuse_ticket_release(fdi.tick);

    if (vnode_vtype(vp) != vap->va_type) {
        if ((vnode_vtype(vp) == VNON) && (vap->va_type != VNON)) {
            /*
             * We should be doing the following:
             *
             * vp->vtype = vap->v_type
             */
        } else {

            /*
             * STALE vnode, ditch
             *
             * The vnode has changed its type "behind our back". There's
             * nothing really we can do, so let us just force an internal
             * revocation.
             */

#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(data->biglock);
#endif
            fuse_internal_vnode_disappear(vp, context, REVOKE_SOFT);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(data->biglock);
#endif
            return EIO;
        }
    }

    return 0;

fake:
    VATTR_RETURN(vap, va_type, vnode_vtype(vp));
    VATTR_RETURN(vap, va_uid, kauth_cred_getuid(data->daemoncred));
    VATTR_RETURN(vap, va_gid, kauth_cred_getgid(data->daemoncred));
    VATTR_RETURN(vap, va_mode, S_IRWXU);

    return 0;
}

#if M_OSXFUSE_ENABLE_XATTR
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
fuse_vnop_getxattr(struct vnop_getxattr_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    const char   *name    = ap->a_name;
    uio_t         uio     = ap->a_uio;
    vfs_context_t context = ap->a_context;

    struct fuse_dispatcher  fdi;
    struct fuse_abi_data    fgxi;
    struct fuse_data       *data;
    mount_t mp;

    int err = 0;
    size_t namelen;
    void *next;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    if (fuse_vfs_context_issuser(context)) {
        /*
         * Note: Starting with OS X 10.9 syspolicyd (which is running as root)
         * calls getxattr(2) when opening items in Finder. Blocking these calls
         * results in Finder displaying an error message. Therefore we are no
         * longer blocking calls by root even if allow_root or allow_other is
         * not set.
         */
    } else {
        CHECK_BLANKET_DENIAL(vp, context, ENOENT);
    }

    if (name == NULL || name[0] == '\0') {
        return EINVAL;
    }

    mp = vnode_mount(vp);
    data = fuse_get_mpdata(mp);

    if (fuse_skip_apple_xattr_mp(mp, name)) {
        return EPERM;
    }

    if (data->dataflags & FSESS_AUTO_XATTR) {
        return ENOTSUP;
    }

    if (!fuse_implemented(data, FSESS_NOIMPLBIT(GETXATTR))) {
        return ENOTSUP;
    }

    namelen = strlen(name);

    fdata_wait_init(data);
    fdisp_init(&fdi, fuse_getxattr_in_sizeof(DATOI(data)) + namelen + 1);
    fdisp_make_vp(&fdi, FUSE_GETXATTR, vp, context);
    fuse_abi_data_init(&fgxi, DATOI(data), fdi.indata);
    next = (char *)fdi.indata + fuse_getxattr_in_sizeof(DATOI(data));

    if (uio) {
        fuse_getxattr_in_set_size(&fgxi, (uint32_t)uio_resid(uio));
        fuse_getxattr_in_set_position(&fgxi, (uint32_t)uio_offset(uio));
    } else {
        fuse_getxattr_in_set_size(&fgxi, 0);
        fuse_getxattr_in_set_position(&fgxi, 0);
    }

    memcpy(next, name, namelen);
    ((char *)next)[namelen] = '\0';

    if (fuse_getxattr_in_get_size(&fgxi) > FUSE_REASONABLE_XATTRSIZE) {
        fticket_set_kill(fdi.tick);
    }

    err = fdisp_wait_answ(&fdi);
    if (err) {
        if (err == ENOSYS) {
            fuse_clear_implemented(data, FSESS_NOIMPLBIT(GETXATTR));
            return ENOTSUP;
        }
        return err;
    }

    if (uio) {
        *ap->a_size = fdi.iosize;
        if ((user_ssize_t)fdi.iosize > uio_resid(uio)) {
            err = ERANGE;
        } else {
            err = uiomove((char *)fdi.answ, (int)fdi.iosize, uio);
        }
    } else {
        struct fuse_abi_data fgxo;

        fuse_abi_data_init(&fgxo, DATOI(data), fdi.answ);
        *ap->a_size = fuse_getxattr_out_get_size(&fgxo);
    }

    fuse_ticket_release(fdi.tick);

    return err;
}
#endif /* M_OSXFUSE_ENABLE_XATTR */

/*
    struct vnop_inactive_args {
        struct vnodeop_desc *a_desc;
        vnode_t              a_vp;
        vfs_context_t        a_context;
    };
*/
FUSE_VNOP_EXPORT
int
fuse_vnop_inactive(struct vnop_inactive_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    vfs_context_t context = ap->a_context;

    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh = NULL;

    int fufh_type;

    fuse_trace_printf_vnop();

    /*
     * Cannot do early bail out on a dead file system in this case.
     */

    for (fufh_type = 0; fufh_type < FUFH_MAXTYPE; fufh_type++) {

        fufh = &(fvdat->fufh[fufh_type]);

        if (FUFH_IS_VALID(fufh)) {
            FUFH_USE_RESET(fufh);
            (void)fuse_filehandle_put(vp, context, fufh_type,
                                      FUSE_OP_FOREGROUNDED);
        }
    }

    return 0;
}

extern int fuse_setextendedsecurity(mount_t mp, int state);

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
fuse_vnop_ioctl(struct vnop_ioctl_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    u_long        cmd     = ap->a_command;
    vfs_context_t context = ap->a_context;

    mount_t mp;
    struct fuse_data *data;

    int err;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(vp, context, EPERM);

    mp = vnode_mount(vp);
    data = fuse_get_mpdata(mp);

    if (cmd == FSCTLSETACLSTATE) {
        int state;

        if (ap->a_data == NULL) {
            return EINVAL;
        }
        state = *(int *)ap->a_data;

        return fuse_setextendedsecurity(mp, state);
    }
    if (cmd == F_FULLFSYNC) {
        return fuse_internal_fsync_vp(vp, context);
    }

    if (!fuse_abi_is_op_supported(DTOABI(data), FUSE_IOCTL) ||
        !fuse_implemented(data, FSESS_NOIMPLBIT(IOCTL))) {
        return EINVAL;
    }

    /* Note: We made sure that IOCTLs are supported by the FUSE server. */

    int param_len = (int)IOCPARM_LEN(cmd);

    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    fufh_type_t fufh_type;
    struct fuse_filehandle *fufh;

    struct fuse_abi_data fioi;
    struct fuse_abi_data fioo;

    struct fuse_dispatcher fdi;
    void *next;

    fufh_type = fuse_filehandle_xlate_from_fflags(ap->a_fflag);
    fufh = &(fvdat->fufh[fufh_type]);

    if (!FUFH_IS_VALID(fufh)) {
        fufh_type = FUFH_RDWR;
        fufh = &(fvdat->fufh[fufh_type]);
        if (!FUFH_IS_VALID(fufh)) {
            fufh = NULL;
        } else {
            /* Falling back to FUFH_RDWR. */
        }
    }

    if (!fufh) {
        /* Failing ioctl because of no fufh. */
        return EIO;
    } else {
        /* Using existing fufh of type fufh_type. */
    }

    /*
	 * Note: Linux FUSE IOCTL flags like FUSE_IOCTL_UNRESTRICTED are not
     * supported on macOS. Enabling unrestricted mode by default would result in
     * security implications. We don't trust the FUSE file system
     * implementation. Therefor fall back on restricted mode.
     *
     * - Initialize I/O parameters as encoded in cmd.
     * - RETRY from server is not allowed.
	 */

    fdata_wait_init(data);
    fdisp_init(&fdi, fuse_ioctl_in_sizeof(DATOI(data)) +
               ((cmd & IOC_IN) ? param_len : 0));
    fdisp_make_vp(&fdi, FUSE_IOCTL, vp, context);

    fuse_abi_data_init(&fioi, DATOI(data), fdi.indata);
    next = (char *)fdi.indata + fuse_ioctl_in_sizeof(DATOI(data));

    fuse_ioctl_in_set_fh(&fioi, fufh->fh_id);
    fuse_ioctl_in_set_flags(&fioi, 0);
    fuse_ioctl_in_set_cmd(&fioi, (uint32_t)cmd);
    fuse_ioctl_in_set_arg(&fioi, (uintptr_t)ap->a_data);

    if (cmd & IOC_IN) {
        fuse_ioctl_in_set_in_size(&fioi, param_len);
    } else {
        fuse_ioctl_in_set_in_size(&fioi, 0);
    }

    if (cmd & IOC_OUT) {
        fuse_ioctl_in_set_out_size(&fioi, param_len);
    } else {
        fuse_ioctl_in_set_out_size(&fioi, 0);
    }

    if (cmd & IOC_IN) {
        memcpy(next, ap->a_data, param_len);
    }

    err = fdisp_wait_answ(&fdi);
    if (err) {
        if (err == ENOSYS) {
            fuse_clear_implemented(data, FSESS_NOIMPLBIT(IOCTL));
            err = EINVAL;
        }
        return err;
    }

    fuse_abi_data_init(&fioo, DATOI(data), fdi.answ);
    next = (char *)fdi.answ + fuse_ioctl_out_sizeof(DATOI(data));
    err = -fuse_ioctl_out_get_result(&fioo);

    if (!err && (ap->a_command & IOC_OUT)) {
        memcpy(ap->a_data, next, param_len);
    }

    fuse_ticket_release(fdi.tick);
    return err;
}

#if M_OSXFUSE_ENABLE_KQUEUE

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
fuse_vnop_kqfilt_add(struct vnop_kqfilt_add_args *ap)
{
    vnode_t       vp = ap->a_vp;
    struct knote *kn = ap->a_kn;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    switch (kn->kn_filter) {
    case EVFILT_READ:
        if (vnode_isreg(vp)) {
            kn->kn_fop = &fuseread_filtops;
        } else {
            return EINVAL;
        }
        break;

    case EVFILT_WRITE:
        if (vnode_isreg(vp)) {
            kn->kn_fop = &fusewrite_filtops;
        } else {
            return EINVAL;
        }
        break;

    case EVFILT_VNODE:
        kn->kn_fop = &fusevnode_filtops;
        break;

    default:
        return 1;
    }

    kn->kn_hook = (caddr_t)vp;
    kn->kn_hookid = vnode_vid(vp);

    /* lock */
    KNOTE_ATTACH(&VTOFUD(vp)->c_knotes, kn);
    /* unlock */

    return 0;
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
fuse_vnop_kqfilt_remove(__unused struct vnop_kqfilt_remove_args *ap)
{
    fuse_trace_printf_vnop_novp();

    return ENOTSUP;
}

#endif /* M_OSXFUSE_ENABLE_KQUEUE */

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
fuse_vnop_link(struct vnop_link_args *ap)
{
    vnode_t               vp      = ap->a_vp;
    vnode_t               tdvp    = ap->a_tdvp;
    struct componentname *cnp     = ap->a_cnp;
    vfs_context_t         context = ap->a_context;

    struct vnode_attr *vap = VTOVA(vp);

    vnode_t tvp = NULL;

    struct fuse_dispatcher  fdi;
    struct fuse_link_in     fli_data;
    struct fuse_abi_data    fli;
    struct fuse_data       *data;

    int err;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_fs(vp)) {
        return ENXIO;
    }

    if (vnode_mount(tdvp) != vnode_mount(vp)) {
        return EXDEV;
    }

    if (vap->va_nlink >= FUSE_LINK_MAX) {
        return EMLINK;
    }

    CHECK_BLANKET_DENIAL(vp, context, EPERM);

    data = fuse_get_mpdata(vnode_mount(vp));

    fdata_wait_init(data);

    fuse_abi_data_init(&fli, DATOI(data), &fli_data);

    fuse_link_in_set_oldnodeid(&fli, VTOI(vp));

    fdisp_init(&fdi, 0);
    fuse_internal_newentry_makerequest(vnode_mount(tdvp), VTOI(tdvp), cnp,
                                       FUSE_LINK, fli.fad_data,
                                       fuse_link_in_sizeof(DATOI(data)),
                                       &fdi, context);

    /* Note: fuse_internal_newentry_core releases fdi.tick */
    err = fuse_internal_newentry_core(tdvp, &tvp, cnp, vnode_vtype(vp), &fdi,
                                      context);

    fuse_invalidate_attr(tdvp);
    fuse_invalidate_attr(vp);

    if (!err) {
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_unlock(data->biglock);
#endif
        vnode_put(tvp);
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_lock(data->biglock);
#endif
    }

    return err;
}

#if M_OSXFUSE_ENABLE_XATTR
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
fuse_vnop_listxattr(struct vnop_listxattr_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    uio_t         uio     = ap->a_uio;
    vfs_context_t context = ap->a_context;

    struct fuse_dispatcher  fdi;
    struct fuse_abi_data    fgxi;
    struct fuse_abi_data    fgxo;
    struct fuse_data       *data;

    int err = 0;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    if (fuse_vfs_context_issuser(context)) {
        /*
         * Note: Do not block calls by root even if allow_root or allow_other
         * is not set. For details see fuse_vnop_getxattr().
         */
    } else {
        CHECK_BLANKET_DENIAL(vp, context, ENOENT);
    }

    data = fuse_get_mpdata(vnode_mount(vp));

    if (data->dataflags & FSESS_AUTO_XATTR) {
        return ENOTSUP;
    }

    if (!fuse_implemented(data, FSESS_NOIMPLBIT(LISTXATTR))) {
        return ENOTSUP;
    }

    fdisp_init_abi(&fdi, fuse_getxattr_in, data);
    fdisp_make_vp(&fdi, FUSE_LISTXATTR, vp, context);
    fuse_abi_data_init(&fgxi, DATOI(data), fdi.indata);

    if (uio) {
        fuse_getxattr_in_set_size(&fgxi, (uint32_t)uio_resid(uio));
    } else {
        fuse_getxattr_in_set_size(&fgxi, 0);
    }

    err = fdisp_wait_answ(&fdi);
    if (err) {
        if (err == ENOSYS) {
            fuse_clear_implemented(data, FSESS_NOIMPLBIT(LISTXATTR));
            return ENOTSUP;
        }
        return err;
    }

    if (uio) {
        *ap->a_size = fdi.iosize;
        if ((user_ssize_t)fdi.iosize > uio_resid(uio)) {
            err = ERANGE;
        } else {
            err = uiomove((char *)fdi.answ, (int)fdi.iosize, uio);
        }
    } else {
        fuse_abi_data_init(&fgxo, DATOI(data), fdi.answ);
        *ap->a_size = fuse_getxattr_out_get_size(&fgxo);
    }

    fuse_ticket_release(fdi.tick);

    return err;
}
#endif /* M_OSXFUSE_ENABLE_XATTR */

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
fuse_vnop_lookup(struct vnop_lookup_args *ap)
{
    vnode_t dvp               = ap->a_dvp;
    vnode_t *vpp              = ap->a_vpp;
    struct componentname *cnp = ap->a_cnp;
    vfs_context_t context     = ap->a_context;

    int nameiop               = cnp->cn_nameiop;
    int flags                 = cnp->cn_flags;
    int wantparent            = flags & (LOCKPARENT|WANTPARENT);
    int islastcn              = flags & ISLASTCN;
    bool isdot                = false;
    bool isdotdot             = false;
    mount_t mp                = vnode_mount(dvp);

    int err                   = 0;
    int lookup_err            = 0;
    vnode_t vp                = NULL;
    vnode_t pdp               = (vnode_t)NULL;

    struct fuse_dispatcher fdi;
    enum   fuse_opcode     op;

    uint64_t nodeid;

    struct fuse_abi_data  fgi;
    struct fuse_data     *data;
    struct fuse_abi_data  feo;
    struct fuse_abi_data  fattr;

    *vpp = NULLVP;

    fuse_trace_printf_vnop_novp();

    if (fuse_isdeadfs(dvp)) {
        *ap->a_vpp = NULLVP;
        return ENXIO;
    }

    if (fuse_skip_apple_double_mp(mp, cnp->cn_nameptr, cnp->cn_namelen)) {
        return ENOENT;
    }

    if (!vnode_isdir(dvp)) {
        return ENOTDIR;
    }

    if (islastcn && vfs_isrdonly(mp) && (nameiop != LOOKUP)) {
        return EROFS;
    }

    if (cnp->cn_namelen > FUSE_MAXNAMLEN) {
        return ENAMETOOLONG;
    }

    if (flags & ISDOTDOT) {
        isdotdot = true;
    } else if ((cnp->cn_nameptr[0] == '.') && (cnp->cn_namelen == 1)) {
        isdot = true;
    }

    data = fuse_get_mpdata(mp);

    if (isdotdot) {
        pdp = VTOFUD(dvp)->parentvp;
        nodeid = VTOI(pdp);
        fdisp_init_abi(&fdi, fuse_getattr_in, data);
        op = FUSE_GETATTR;
        goto calldaemon;
    } else if (isdot) {
        nodeid = VTOI(dvp);
        fdisp_init_abi(&fdi, fuse_getattr_in, data);
        op = FUSE_GETATTR;
        goto calldaemon;
    } else {
        err = fuse_vncache_lookup(dvp, vpp, cnp);
        switch (err) {

        case -1: /* positive match */
            /* We ignore cache hits when trying to create a file.
             * Indeed, the file could have disappeared below us,
             * and we do not want to return EEXIST in that case,
             * so we let the underlying filesystem decide. */
            if (fuse_isnovncache(*vpp) || (nameiop == CREATE)) {
                fuse_vncache_purge(*vpp);
#if M_OSXFUSE_ENABLE_BIG_LOCK
                fuse_biglock_unlock(data->biglock);
#endif
                vnode_put(*vpp);
#if M_OSXFUSE_ENABLE_BIG_LOCK
                fuse_biglock_lock(data->biglock);
#endif
                *vpp = NULL;
                FUSE_OSAddAtomic(1, (SInt32 *)&fuse_lookup_cache_overrides);
                break; /* pretend it's a miss */
            }
            FUSE_OSAddAtomic(1, (SInt32 *)&fuse_lookup_cache_hits);
            return 0;

        case 0: /* no match in cache (or aged out) */
            FUSE_OSAddAtomic(1, (SInt32 *)&fuse_lookup_cache_misses);
            break;

        case ENOENT: /* negative match */
             /* fall through */
        default:
             return err;
        }
    }

    nodeid = VTOI(dvp);
    fdisp_init(&fdi, cnp->cn_namelen + 1);
    op = FUSE_LOOKUP;

calldaemon:
    fdisp_make(&fdi, op, mp, nodeid, context);

    if (op == FUSE_LOOKUP) {
        memcpy(fdi.indata, cnp->cn_nameptr, cnp->cn_namelen);
        ((char *)fdi.indata)[cnp->cn_namelen] = '\0';
    } else if (op == FUSE_GETATTR) {
        fuse_abi_data_init(&fgi, DATOI(data), fdi.indata);
        fuse_getattr_in_set_getattr_flags(&fgi, 0);
        fuse_getattr_in_set_fh(&fgi, 0);
    }

    lookup_err = fdisp_wait_answ(&fdi);

    if ((op == FUSE_LOOKUP) && !lookup_err) { /* lookup call succeeded */
        fuse_abi_data_init(&feo, DATOI(data), fdi.answ);
        nodeid = fuse_entry_out_get_nodeid(&feo);
        if (!nodeid) {
            fdi.answ_stat = ENOENT; /* XXX: negative_timeout case */
            lookup_err = ENOENT;

            fuse_ticket_release(fdi.tick);
            fdi.tick = NULL;
        } else if (nodeid == FUSE_ROOT_ID) {
            lookup_err = EINVAL;

            fuse_ticket_release(fdi.tick);
            fdi.tick = NULL;
        }
    } else {
        feo.fad_data = NULL;
    }

    /*
     * If we get (lookup_err != 0), that means we didn't find what we were
     * looking for. This can still be OK if we're creating or renaming and
     * are at the end of the pathname.
     */

    if (lookup_err &&
        (!fdi.answ_stat || lookup_err != ENOENT || op != FUSE_LOOKUP)) {
        return lookup_err;
    }

    /* lookup_err, if non-zero, must be ENOENT at this point */

    if (lookup_err) {

        if ((nameiop == CREATE || nameiop == RENAME) && islastcn
            /* && directory dvp has not been removed */) {

            /*
             * EROFS case has already been covered.
             *
             * if (vfs_isrdonly(mp)) {
             *     err = EROFS;
             *     goto out;
             * }
             */

            err = EJUSTRETURN;
            goto out;
        }

        if (fuse_isnegativevncache_mp(mp)) {
            if ((cnp->cn_flags & MAKEENTRY) && (nameiop != CREATE)) {
                fuse_vncache_enter(dvp, NULLVP, cnp);
            }
        }

        err = ENOENT;
        goto out;

    } else {

        /* !lookup_err */

        struct fuse_abi_data fao;

        fuse_abi_data_init(&fao, DATOI(data), NULL);
        if (op == FUSE_GETATTR) {
            fuse_abi_data_init(&fao, DATOI(data), fdi.answ);
            fuse_abi_data_init(&fattr, fao.fad_version, fuse_attr_out_get_attr(&fao));
        } else {
            fuse_abi_data_init(&fattr, feo.fad_version, fuse_entry_out_get_attr(&feo));
        }

        /* Sanity check(s) */

        if ((fuse_attr_get_mode(&fattr) & S_IFMT) == 0) {
            err = EIO;
            goto out;
        }

        if ((nameiop == RENAME) && islastcn && wantparent) {

            if (isdot) {
                err = EISDIR;
                goto out;
            }

            if ((err = fuse_vget_i(&vp, 0 /* flags */, &feo, cnp, dvp, mp,
                                   context))) {
                goto out;
            }

            *vpp = vp;

            goto out;
        }

        if (isdotdot) {
            err = vnode_get(pdp);
            if (err == 0) {
                *vpp = pdp;
            }
        } else if (isdot) { /* nodeid == VTOI(dvp) */
            err = vnode_get(dvp);
            if (err == 0) {
                *vpp = dvp;
            }
        } else {
            if ((err  = fuse_vget_i(&vp, 0 /* flags */, &feo, cnp, dvp,
                                    mp, context))) {
                goto out;
            }
            *vpp = vp;
        }

        /*
         * Do not mess with *vpp's filesize or attributes. Doing so can cause data
         * corruption in case the file is currently being appended.
         *
         * // ATTR_FUDGE_CASE
         * if (vnode_isreg(*vpp) && fuse_isnoubc(vp)) {
         *     VTOFUD(*vpp)->filesize = fuse_attr_get_size(&fattr);
         * }
         *
         * if (op == FUSE_GETATTR) {
         *     cache_attrs(*vpp, fuse_attr_out, &fao);
         * } else {
         *     cache_attrs(*vpp, fuse_entry_out, &feo);
         * }
         */

        /*
         * We do this elsewhere...
         *
         * if (cnp->cn_flags & MAKEENTRY) {
         *     fuse_vncache_enter(dvp, *vpp, cnp);
         * }
         */
    }

out:
    if (!lookup_err) {

        /* No lookup error; need to clean up. */

        if (err) { /* Found inode; exit with no vnode. */
            if (op == FUSE_LOOKUP) {
                fuse_internal_forget_send(vnode_mount(dvp), context,
                                          nodeid, 1, &fdi);
            }
        } else {

            if (!islastcn) {

                int tmpvtype = vnode_vtype(*vpp);

                if ((tmpvtype != VDIR) && (tmpvtype != VLNK)) {
                    err = ENOTDIR;
                }

                /* if (!err && !vnode_mountedhere(*vpp)) { ... */

                if (err) {
#if M_OSXFUSE_ENABLE_BIG_LOCK
                    fuse_biglock_unlock(data->biglock);
#endif
                    vnode_put(*vpp);
#if M_OSXFUSE_ENABLE_BIG_LOCK
                    fuse_biglock_lock(data->biglock);
#endif
                    *vpp = NULL;
                }
            }
        }

        fuse_ticket_release(fdi.tick);
    }

    return err;
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
fuse_vnop_mkdir(struct vnop_mkdir_args *ap)
{
    vnode_t               dvp     = ap->a_dvp;
    vnode_t              *vpp     = ap->a_vpp;
    struct componentname *cnp     = ap->a_cnp;
    struct vnode_attr    *vap     = ap->a_vap;
    vfs_context_t         context = ap->a_context;

    int err = 0;

    struct fuse_data     *data;
    struct fuse_mkdir_in  fmdi_data;
    struct fuse_abi_data  fmdi;

    fuse_trace_printf_vnop_novp();

    if (fuse_isdeadfs_fs(dvp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(dvp, context, EPERM);

    data = fuse_get_mpdata(vnode_mount(dvp));

    fdata_wait_init(data);
    fuse_abi_data_init(&fmdi, DATOI(data), &fmdi_data);

    fuse_mkdir_in_set_mode(&fmdi, MAKEIMODE(vap->va_type, vap->va_mode));
    fuse_mkdir_in_set_umask(&fmdi, 0);

    err = fuse_internal_newentry(dvp, vpp, cnp, FUSE_MKDIR, fmdi.fad_data,
                                 fuse_mkdir_in_sizeof(DATOI(data)),
                                 VDIR, context);

    if (err == 0) {
        fuse_invalidate_attr(dvp);
    }

    return err;
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
fuse_vnop_mknod(struct vnop_mknod_args *ap)
{
    vnode_t               dvp     = ap->a_dvp;
    vnode_t              *vpp     = ap->a_vpp;
    struct componentname *cnp     = ap->a_cnp;
    struct vnode_attr    *vap     = ap->a_vap;
    vfs_context_t         context = ap->a_context;

    struct fuse_data     *data;
    struct fuse_mknod_in  fmni_data;
    struct fuse_abi_data  fmni;

    int err;

    fuse_trace_printf_vnop_novp();

    if (fuse_isdeadfs_fs(dvp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(dvp, context, EPERM);

    data = fuse_get_mpdata(vnode_mount(dvp));

    fdata_wait_init(data);
    fuse_abi_data_init(&fmni, DATOI(data), &fmni_data);

    fuse_mknod_in_set_mode(&fmni, MAKEIMODE(vap->va_type, vap->va_mode));
    fuse_mknod_in_set_rdev(&fmni, vap->va_rdev);
    fuse_mknod_in_set_umask(&fmni, 0);

    err = fuse_internal_newentry(dvp, vpp, cnp, FUSE_MKNOD, fmni.fad_data,
                                 fuse_mknod_in_sizeof(DATOI(data)),
                                 vap->va_type, context);

    if (err == 0) {
        fuse_invalidate_attr(dvp);
    }

    return err;
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
fuse_vnop_mmap(struct vnop_mmap_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    int           fflags  = ap->a_fflags;
    vfs_context_t context = ap->a_context;

    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh = NULL;
    fufh_type_t fufh_type = fuse_filehandle_xlate_from_mmap(fflags);

    int err = 0;
    int deleted = 0;
    int retried = 0;
    int preflight = 0;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_fs(vp)) {
        return ENXIO;
    }

    if (fuse_isdirectio(vp)) {
        return ENODEV;
    }

    CHECK_BLANKET_DENIAL(vp, context, ENOENT);

    if (fufh_type == FUFH_INVALID) { /* nothing to do */
        return 0;
    }

    /* XXX: For PROT_WRITE, we should only care if file is mapped MAP_SHARED. */

retry:
    fufh = &(fvdat->fufh[fufh_type]);

    if (FUFH_IS_VALID(fufh)) {
        FUFH_USE_INC(fufh);
        FUSE_OSAddAtomic(1, (SInt32 *)&fuse_fh_reuse_count);
        goto out;
    }

    if (!deleted && !preflight) {
#if M_OSXFUSE_ENABLE_BIG_LOCK
        struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));

        /*
         * fuse_filehandle_preflight_status eventually calls vnode_authorize
         * which might call VNOP_GETATTR. Release biglock and fusenode lock to
         * prevent a deadlock.
         *
         * Releasing the fusenode lock during a vnop is dangerous, but it is
         * considered safe at this point:
         *
         * - fufh_type is determined by fflags which is not going to change.
         * - We make sure that no other thread opens the file while the
         *   fusenode lock is released before proceeding.
         */
        fuse_biglock_unlock(data->biglock);
        fuse_nodelock_unlock(fvdat);
#endif
        err = fuse_filehandle_preflight_status(vp, fvdat->parentvp,
                                               context, fufh_type);
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_nodelock_lock(fvdat, FUSEFS_EXCLUSIVE_LOCK);
        fuse_biglock_lock(data->biglock);
#endif

        if (err == ENOENT) {
            deleted = 1;
            err = 0;
        }

#if M_OSXFUSE_ENABLE_BIG_LOCK
        /*
         * Make sure that no other thread created a valid file handle by calling
         * fuse_filehandle_get while the fusenode lock was released. Calling
         * fuse_filehandle_get on a valid file handle results in a kernel panic.
         */
        preflight = 1;
        goto retry;
#endif
    }
    preflight = 0;

#if FUSE_DEBUG
    fuse_preflight_log(vp, fufh_type, err, "mmap");
#endif /* FUSE_DEBUG */

    if (!err) {
        err = fuse_filehandle_get(vp, context, fufh_type, 0 /* mode */);
    }

    if (err) {
        /*
         * XXX: This is a kludge because xnu doesn't tell us whether this
         *      is a MAP_SHARED or MAP_PRIVATE mapping. If we want shared
         *      library mapping to go well, we need to do this.
         */
        if (!retried && (err == EACCES) &&
            ((fufh_type == FUFH_RDWR) || (fufh_type == FUFH_WRONLY))) {
            IOLog("osxfuse: filehandle_get retrying (type=%d, err=%d)\n",
                  fufh_type, err);
            fufh_type = FUFH_RDONLY;
            retried = 1;
            goto retry;
        } else {
            IOLog("osxfuse: filehandle_get failed in mmap (type=%d, err=%d)\n",
                  fufh_type, err);
        }
        return EPERM;
    }

out:

    return 0;
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
fuse_vnop_mnomap(struct vnop_mnomap_args *ap)
{
    vnode_t vp = ap->a_vp;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return 0;
    }

    if (fuse_isdirectio(vp)) {
        /*
         * ubc_unmap() doesn't care about the return value.
         */
        return ENODEV;
    }

    /*
     * munmap(2) states:
     *
     *   If the mapping maps data from a file (MAP_SHARED), then the memory will
     *   eventually be written back to disk if it's dirty. This will happen
     *   automatically at some point in the future (implementation dependent).
     *
     * In our case this point is now. Maintaining a consistent file state on the
     * backing storage is important if we are dealing with distributed file
     * systems.
     *
     * Note:
     *
     * fuse_vnop_mnomap() is called when there are no more references to the
     * file's mapped data. In other words, we have no definate way of knowing
     * when a particular process unmaps a file since the file's data might
     * still be referenced by other processes (MAP_SHARED).
     *
     * Calling ubc_msync() in fuse_vnop_close() is not going to help because
     * the close(2) system call does not unmap the file. See mmap(2).
     *
     * Since vnop mnomap is considered a hint, returned errors are being
     * ignored. See ubc_unmap(). As a result ubc_msync() might fail without the
     * error being propagated back to user space.
     */

#if M_OSXFUSE_ENABLE_BIG_LOCK
    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));
    fuse_biglock_unlock(data->biglock);
#endif
    (void)ubc_msync(vp, (off_t)0, ubc_getsize(vp), NULL, UBC_PUSHDIRTY);
#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_lock(data->biglock);
#endif

    /*
     * Earlier, we used to go through our vnode's fufh list here, doing
     * something like the following:
     *
     * for (type = 0; type < FUFH_MAXTYPE; type++) {
     *     fufh = &(fvdat->fufh[type]);
     *     if ((fufh->fufh_flags & FUFH_VALID) &&
     *         (fufh->fufh_flags & FUFH_MAPPED)) {
     *         fufh->fufh_flags &= ~FUFH_MAPPED;
     *         if (fufh->open_count == 0) {
     *             (void)fuse_filehandle_put(vp, context, type,
     *                                       FUSE_OP_BACKGROUNDED);
     *         }
     *     }
     * }
     *
     * Now, cleanup is all taken care of in vnop_inactive/reclaim.
     */

    return 0;
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
fuse_vnop_offtoblk(struct vnop_offtoblk_args *ap)
{
    vnode_t    vp        = ap->a_vp;
    off_t      offset    = ap->a_offset;
    daddr64_t *lblknoPtr = ap->a_lblkno;

    struct fuse_data *data;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    data = fuse_get_mpdata(vnode_mount(vp));

    *lblknoPtr = offset / data->blocksize;

    return 0;
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
fuse_vnop_open(struct vnop_open_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    int           mode    = ap->a_mode;
    vfs_context_t context = ap->a_context;

    bool blanket_allow = false;

    fufh_type_t             fufh_type;
    struct fuse_vnode_data *fvdat;
    struct fuse_filehandle *fufh = NULL;
    struct fuse_filehandle *fufh_rw = NULL;

    int error, isdir = 0;

    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

#if !M_OSXFUSE_ENABLE_FIFOFS
    if (vnode_isfifo(vp)) {
        return EPERM;
    }
#endif

    if (fuse_vfs_context_issuser(context)) {
        /*
         * Note: Do not block calls from syspolicyd even if allow_root or
         * allow_other is not set. For details see fuse_vnop_getxattr().
         */

        char name[MAXCOMLEN + 1];
        proc_selfname(name, sizeof(name));
        blanket_allow = strncmp(name, "syspolicyd", sizeof("syspolicyd")) == 0;
    }

    if (!blanket_allow) {
        CHECK_BLANKET_DENIAL(vp, context, ENOENT);
    }

    fvdat = VTOFUD(vp);

    if (vnode_isdir(vp)) {
        isdir = 1;
    }

    if (isdir) {
        fufh_type = FUFH_RDONLY;
    } else {
        fufh_type = fuse_filehandle_xlate_from_fflags(mode);
    }

    fufh = &(fvdat->fufh[fufh_type]);

    if (!isdir && (fvdat->flag & FN_CREATING)) {

        fuse_lck_mtx_lock(fvdat->createlock);

        if (fvdat->flag & FN_CREATING) { // check again
            if (fvdat->creator == current_thread()) {

                /*
                 * For testing the race condition we want to prevent here,
                 * try something like the following:
                 *
                 *     int dummyctr = 0;
                 *
                 *     for (; dummyctr < 2048000000; dummyctr++);
                 */

                fufh_rw = &(fvdat->fufh[FUFH_RDWR]);

                fufh->open_flags = fufh_rw->open_flags;
                fufh->fh_id = fufh_rw->fh_id;

                /* Note that fufh_rw can be the same as fufh! Order is key. */
                fufh_rw->open_count = 0;
                fufh->open_count = 1;

                /*
                 * Creator has picked up stashed handle and moved it to the
                 * fufh_type slot.
                 */

                fvdat->flag &= ~FN_CREATING;

                fuse_lck_mtx_unlock(fvdat->createlock);
                fuse_wakeup((caddr_t)fvdat->creator); // wake up all
                goto ok; /* return 0 */
            } else {

                /* Contender is going to sleep now. */

#if M_OSXFUSE_ENABLE_BIG_LOCK
                /*
                 * We assume, that a call to fuse_vnop_create is always
                 * followed by a call to fuse_vnop_open by the same thread.
                 *
                 * Once fuse_vnop_create returns, the vnode of the new file is
                 * accessible in subsequent fuse_vnop_lookup calls. This allows
                 * contenders to look up the vnode and try to open the file
                 * between the call to fuse_vnop_create and fuse_vnop_open.
                 * Contenders are prevented from completing the call to
                 * fuse_vnop_open as long as the flag FN_CREATING is set.
                 *
                 * Release biglock and fusenode lock before going to sleep, to
                 * allow the creator to enter fuse_vnop_open, clear the flag
                 * FN_CREATING and wake up the contenders. Releasing the
                 * fusenode lock during a vnop is dangerous, but it is
                 * considered safe at this point:
                 *
                 * - fufh_type is determined by the type of the vnode, which is
                 *   not going to change.
                 * - fufh points to the file handle determined by fufh_type and
                 *   is verified after the contender is woken up.
                 */
                fuse_biglock_unlock(data->biglock);
                fuse_nodelock_unlock(VTOFUD(vp));
#endif
                error = fuse_msleep(fvdat->creator, fvdat->createlock,
                                    PDROP | PINOD | PCATCH, "fuse_open", NULL, NULL);
#if M_OSXFUSE_ENABLE_BIG_LOCK
                fuse_nodelock_lock(VTOFUD(vp), FUSEFS_EXCLUSIVE_LOCK);
                fuse_biglock_lock(data->biglock);
#endif

                /*
                 * msleep will drop the mutex. since we have PDROP specified,
                 * it will NOT regrab the mutex when it returns.
                 */

                /* Contender is awake now. */

                if (error) {
                    /*
                     * Since we specified PCATCH above, we'll be woken up in
                     * case a signal arrives. The value of error could be
                     * EINTR or ERESTART.
                     */
                    return error;
                }
            }
        } else {
            fuse_lck_mtx_unlock(fvdat->createlock);
            /* Can proceed from here. */
        }
    }

    if (FUFH_IS_VALID(fufh)) {
        FUFH_USE_INC(fufh);
        FUSE_OSAddAtomic(1, (SInt32 *)&fuse_fh_reuse_count);
        goto ok; /* return 0 */
    }

    error = fuse_filehandle_get(vp, context, fufh_type, mode);
    if (error) {
        IOLog("osxfuse: filehandle_get failed in open (type=%d, err=%d)\n",
              fufh_type, error);
        if (error == ENOENT) {
            cache_purge(vp);
        }
        return error;
    }

ok:
    /*
     * Doing this here because when a vnode goes inactive, things like
     * no-cache and no-readahead are cleared by the kernel.
     */

    if ((fufh->fuse_open_flags & FOPEN_DIRECT_IO) || (fuse_isdirectio(vp))) {
        /*
         * direct_io for a vnode implies:
         * - no ubc for the vnode
         * - no readahead for the vnode
         * - nosyncwrites disabled FOR THE ENTIRE MOUNT
         * - no vncache for the vnode (handled in lookup)
         */
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_unlock(data->biglock);
#endif
        ubc_msync(vp, (off_t)0, ubc_getsize(vp), NULL,
                  UBC_PUSHALL | UBC_INVALIDATE);
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_lock(data->biglock);
#endif
        vnode_setnocache(vp);
        vnode_setnoreadahead(vp);
        fuse_clearnosyncwrites_mp(vnode_mount(vp));
        fvdat->flag |= FN_DIRECT_IO;
        goto out;
    } else if (fufh->fuse_open_flags & FOPEN_PURGE_UBC) {
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_unlock(data->biglock);
#endif
        ubc_msync(vp, (off_t)0, ubc_getsize(vp), NULL,
                  UBC_PUSHALL | UBC_INVALIDATE);
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_lock(data->biglock);
#endif
        fufh->fuse_open_flags &= ~FOPEN_PURGE_UBC;
        if (fufh->fuse_open_flags & FOPEN_PURGE_ATTR) {
            struct fuse_dispatcher fdi;
            struct fuse_abi_data fgi;

            fuse_invalidate_attr(vp);

            fdisp_init_abi(&fdi, fuse_getattr_in, data);
            fdisp_make_vp(&fdi, FUSE_GETATTR, vp, context);
            fuse_abi_data_init(&fgi, DATOI(data), fdi.indata);

            fuse_getattr_in_set_getattr_flags(&fgi, FUSE_GETATTR_FH);
            fuse_getattr_in_set_fh(&fgi, fufh->fh_id);

            if (!fdisp_wait_answ(&fdi)) {
                struct fuse_abi_data fao;
                struct fuse_abi_data fa;

                fuse_abi_data_init(&fao, DATOI(data), fdi.answ);
                fuse_abi_data_init(&fa, fao.fad_version, fuse_attr_out_get_attr(&fao));

                /* XXX: Could check the sanity/volatility of va_mode here. */
                if ((fuse_attr_get_mode(&fa) & S_IFMT)) {
                    cache_attrs(vp, fuse_attr_out, &fao);
                    off_t new_filesize = fuse_attr_get_size(&fa);
                    VTOFUD(vp)->filesize = new_filesize;
#if M_OSXFUSE_ENABLE_BIG_LOCK
                    fuse_biglock_unlock(data->biglock);
#endif
                    ubc_setsize(vp, (off_t)new_filesize);
#if M_OSXFUSE_ENABLE_BIG_LOCK
                    fuse_biglock_lock(data->biglock);
#endif
                }
                fuse_ticket_release(fdi.tick);
            }
            fufh->fuse_open_flags &= ~FOPEN_PURGE_ATTR;
        }
    }

    if (fuse_isnoreadahead(vp)) {
        vnode_setnoreadahead(vp);
    }

    if (fuse_isnoubc(vp)) {
        vnode_setnocache(vp);
    }

out:
    return 0;
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
fuse_vnop_pagein(struct vnop_pagein_args *ap)
{
    vnode_t       vp        = ap->a_vp;
    upl_t         pl        = ap->a_pl;
    vm_offset_t   pl_offset = ap->a_pl_offset;
    off_t         f_offset  = ap->a_f_offset;
    size_t        size      = ap->a_size;
    int           flags     = ap->a_flags;

    struct fuse_vnode_data *fvdat;
    int err;

#if M_OSXFUSE_ENABLE_BIG_LOCK
    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));
#endif

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp) || fuse_isdirectio(vp)) {
        if (!(flags & UPL_NOCOMMIT)) {
            ubc_upl_abort_range(pl, (upl_offset_t)pl_offset, (int)size,
                                UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR);
        }
        /*
         * Will cause PAGER_ERROR (pager unable to read or write page).
         */
        return ENOTSUP;
    }

    fvdat = VTOFUD(vp);
    if (!fvdat) {
        return EIO;
    }

#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_unlock(data->biglock);
#endif
    err = cluster_pagein(vp, pl, (upl_offset_t)pl_offset, f_offset, (int)size,
                         fvdat->filesize, flags);
#if M_OSXFUSE_ENABLE_BIG_LOCK
   fuse_biglock_lock(data->biglock);
#endif

    return err;
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
fuse_vnop_pageout(struct vnop_pageout_args *ap)
{
    vnode_t       vp        = ap->a_vp;
    upl_t         pl        = ap->a_pl;
    vm_offset_t   pl_offset = ap->a_pl_offset;
    off_t         f_offset  = ap->a_f_offset;
    size_t        size      = ap->a_size;
    int           flags     = ap->a_flags;

    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    int error;

#if M_OSXFUSE_ENABLE_BIG_LOCK
    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));
#endif

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp) || fuse_isdirectio(vp)) {
        if (!(flags & UPL_NOCOMMIT)) {
            ubc_upl_abort_range(pl, (upl_offset_t)pl_offset, (upl_size_t)size,
                                UPL_ABORT_FREE_ON_EMPTY | UPL_ABORT_ERROR);
        }
        /*
         * Will cause PAGER_ERROR (pager unable to read or write page).
         */
        return ENOTSUP;
    }

#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_unlock(data->biglock);
#endif
    error = cluster_pageout(vp, pl, (upl_offset_t)pl_offset, f_offset,
                            (int)size, (off_t)fvdat->filesize, flags);
#if M_OSXFUSE_ENABLE_BIG_LOCK
   fuse_biglock_lock(data->biglock);
#endif

    return error;
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
fuse_vnop_pathconf(struct vnop_pathconf_args *ap)
{
    vnode_t        vp        = ap->a_vp;
    int            name      = ap->a_name;
    int           *retvalPtr = ap->a_retval;
    vfs_context_t  context   = ap->a_context;

    int err;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(vp, context, ENOENT);

    err = 0;
    switch (name) {
        case _PC_LINK_MAX:
            *retvalPtr = FUSE_LINK_MAX;
            break;
        case _PC_NAME_MAX:
            *retvalPtr = FUSE_MAXNAMLEN;
            break;
        case _PC_PATH_MAX:
            *retvalPtr = MAXPATHLEN;
            break;
        case _PC_PIPE_BUF:
            *retvalPtr = PIPE_BUF;
            break;
        case _PC_CHOWN_RESTRICTED:
            *retvalPtr = 1;
            break;
        case _PC_NO_TRUNC:
            *retvalPtr = 0;
            break;
        case _PC_NAME_CHARS_MAX:
            *retvalPtr = 255;   // chars as opposed to bytes
            break;
        case _PC_CASE_SENSITIVE:
            *retvalPtr = 1;
            break;
        case _PC_CASE_PRESERVING:
            *retvalPtr = 1;
            break;

        /*
         * _PC_EXTENDED_SECURITY_NP and _PC_AUTH_OPAQUE_NP are handled
         * by the VFS.
         */

        // The following are terminal device stuff that we don't support:

        case _PC_MAX_CANON:
        case _PC_MAX_INPUT:
        case _PC_VDISABLE:
        default:
            err = EINVAL;
            break;
    }

    return err;
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
fuse_vnop_read(struct vnop_read_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    uio_t         uio     = ap->a_uio;
    int           ioflag  = ap->a_ioflag;
    vfs_context_t context = ap->a_context;

    struct fuse_vnode_data *fvdat;
    struct fuse_data       *data;

    off_t orig_resid;
    off_t orig_offset;

    int err = EIO;

    /*
     * XXX: Locking
     *
     * lock_shared(truncatelock)
     * call the cluster layer (note that we are always block-aligned)
     * lock(nodelock)
     * do cleanup
     * unlock(nodelock)
     * unlock(truncatelock)
     */

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp) && !vnode_isinuse(vp, 0)) {
        if (!vnode_ischr(vp)) {
            return ENXIO;
        } else {
            return 0;
        }
    }

    if (!vnode_isreg(vp)) {
        if (vnode_isdir(vp)) {
            return EISDIR;
        } else {
            return EPERM;
        }
    }

    /*
     * if (uio_offset(uio) > SOME_MAXIMUM_SIZE) {
     *     return 0;
     * }
     */

    orig_resid = uio_resid(uio);
    if (orig_resid == 0) {
        return 0;
    }

    orig_offset = uio_offset(uio);
    if (orig_offset < 0) {
        return EINVAL;
    }

    fvdat = VTOFUD(vp);
    if (!fvdat) {
        return EINVAL;
    }

    /* Protect against size change here. */

    data = fuse_get_mpdata(vnode_mount(vp));

    if (!fuse_isdirectio(vp)) {
        int res;
        if (fuse_isnoubc(vp)) {
            /* In case we get here through a short cut (e.g. no open). */
            ioflag |= IO_NOCACHE;
        }
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_unlock(data->biglock);
#endif
        res = cluster_read(vp, uio, fvdat->filesize, ioflag);
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_lock(data->biglock);
#endif
        return res;
    }

    /* direct_io */
    {
        fufh_type_t             fufh_type = FUFH_RDONLY;
        struct fuse_dispatcher  fdi;
        struct fuse_filehandle *fufh = NULL;
        struct fuse_abi_data    fri;

        fufh = &(fvdat->fufh[fufh_type]);

        if (!FUFH_IS_VALID(fufh)) {
            fufh_type = FUFH_RDWR;
            fufh = &(fvdat->fufh[fufh_type]);
            if (!FUFH_IS_VALID(fufh)) {
                fufh = NULL;
            } else {
                /* Read falling back to FUFH_RDWR. */
            }
        }

        if (!fufh) {
            /* Failing direct I/O because of no fufh. */
            return EIO;
        } else {
            /* Using existing fufh of type fufh_type. */
        }

        fdata_wait_init(data);
        fdisp_init(&fdi, 0);

        while (uio_resid(uio) > 0) {
            fdi.iosize = fuse_read_in_sizeof(DATOI(data));
            fdisp_make_vp(&fdi, FUSE_READ, vp, context);
            fuse_abi_data_init(&fri, DATOI(data), fdi.indata);

            fuse_read_in_set_fh(&fri, fufh->fh_id);
            fuse_read_in_set_offset(&fri, uio_offset(uio));
            fuse_read_in_set_size(&fri, (uint32_t)min((size_t)uio_resid(uio), VTOVA(vp)->va_iosize));
            fuse_read_in_set_flags(&fri, 0);

            err = fdisp_wait_answ(&fdi);
            if (err) {
                return err;
            }

#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(data->biglock);
#endif
            err = uiomove(fdi.answ, (int)min(fuse_read_in_get_size(&fri), fdi.iosize), uio);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(data->biglock);
#endif
            if (err) {
                break;
            }

            if (fdi.iosize < fuse_read_in_get_size(&fri)) {
                err = -1;
                break;
            }
        }

        if (fdi.tick) {
            fuse_ticket_release(fdi.tick);
        }

    } /* direct_io */

    return ((err == -1) ? 0 : err);
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
fuse_vnop_readdir(struct vnop_readdir_args *ap)
{
    vnode_t        vp           = ap->a_vp;
    uio_t          uio          = ap->a_uio;
    int            flags        = ap->a_flags;
    __unused int  *eofflagPtr   = ap->a_eofflag;
    int           *numdirentPtr = ap->a_numdirent;
    vfs_context_t  context      = ap->a_context;

    struct fuse_filehandle *fufh = NULL;
    struct fuse_vnode_data *fvdat;
    struct fuse_iov         cookediov;

    int err = 0;
    int freefufh = 0;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(vp, context, EPERM);

    /* No cookies yet. */
    if (flags & (VNODE_READDIR_REQSEEKOFF)) {
        return EINVAL;
    }

#define DE_SIZE (int)(sizeof(struct fuse_dirent))

    if ((uio_iovcnt(uio) > 1) ||
        (uio_resid(uio) < (user_ssize_t)DE_SIZE)) {
        return EINVAL;
    }

    /*
     *  if ((uio_offset(uio) % DE_SIZE) != 0) { ...
     */

    fvdat = VTOFUD(vp);

    fufh = &(fvdat->fufh[FUFH_RDONLY]);

    if (!FUFH_IS_VALID(fufh)) {
        err = fuse_filehandle_get(vp, context, FUFH_RDONLY, 0 /* mode */);
        if (err) {
            IOLog("osxfuse: filehandle_get failed in readdir (err=%d)\n", err);
            return err;
        }
        freefufh = 1;
    } else {
        FUSE_OSAddAtomic(1, (SInt32 *)&fuse_fh_reuse_count);
    }

#define DIRCOOKEDSIZE FUSE_DIRENT_ALIGN(FUSE_NAME_OFFSET + MAXNAMLEN + 1)

    fiov_init(&cookediov, DIRCOOKEDSIZE);

    err = fuse_internal_readdir(vp, uio, flags, context, fufh, &cookediov,
                                numdirentPtr);

    fiov_teardown(&cookediov);

    if (freefufh) {
        FUFH_USE_DEC(fufh);
        (void)fuse_filehandle_put(vp, context, FUFH_RDONLY,
                                  FUSE_OP_FOREGROUNDED);
    }

    fuse_invalidate_attr(vp);

    if (err != 0) {
        IOLog("osxfuse: fuse_vnop_readdir failed (err=%d)\n", err);
    }
    return err;
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
fuse_vnop_readlink(struct vnop_readlink_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    uio_t         uio     = ap->a_uio;
    vfs_context_t context = ap->a_context;

    struct fuse_dispatcher fdi;
    int err;

#if M_OSXFUSE_ENABLE_BIG_LOCK
    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));
#endif

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(vp, context, ENOENT);

    if (!vnode_islnk(vp)) {
        return EINVAL;
    }

    err = fdisp_simple_putget_vp(&fdi, FUSE_READLINK, vp, context);
    if (err) {
        return err;
    }

    if (((char *)fdi.answ)[0] == '/' &&
        fuse_get_mpdata(vnode_mount(vp))->dataflags & FSESS_JAIL_SYMLINKS) {
            char *mpth = vfs_statfs(vnode_mount(vp))->f_mntonname;
            err = uiomove(mpth, (int)strlen(mpth), uio);
    }

    if (!err) {
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_unlock(data->biglock);
#endif
        err = uiomove(fdi.answ, (int)fdi.iosize, uio);
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_lock(data->biglock);
#endif
    }

    fuse_ticket_release(fdi.tick);
    fuse_invalidate_attr(vp);

    return err;
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
fuse_vnop_reclaim(struct vnop_reclaim_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    vfs_context_t context = ap->a_context;

    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh = NULL;

    int type;
    HNodeRef hn;

    fuse_trace_printf_vnop();

    if (!fvdat) {
        panic("osxfuse: no vnode data during recycling");
    }

    /*
     * Cannot do early bail out on a dead file system in this case.
     */

    for (type = 0; type < FUFH_MAXTYPE; type++) {
        fufh = &(fvdat->fufh[type]);
        if (FUFH_IS_VALID(fufh)) {
            int open_count = fufh->open_count;
            int aux_count = fufh->aux_count;
            FUFH_USE_RESET(fufh);
            if (vfs_isforce(vnode_mount(vp))) {
                (void)fuse_filehandle_put(vp, context, type,
                                          FUSE_OP_FOREGROUNDED);
            } else {

                /*
                 * This is not a forced unmount. So why is the vnode being
                 * reclaimed if a fufh is valid? Well...
                 *
                 * One reason is that we are dead.
                 *
                 * Another reason is an unmount-time vlush race with ongoing
                 * vnops. Typically happens for a VDIR here.
                 *
                 * More often, the following happened:
                 *
                 *     open()
                 *     mmap()
                 *     close()
                 *     pagein... read... strategy
                 *     done... reclaim
                 */

                if (!fuse_isdeadfs(vp)) {

                    /*
                     * Miselading symptoms (can be seen at unmount time):
                     *
                     * open
                     * close
                     * inactive
                     * open
                     * reclaim <--
                     *
                     */

                    if (open_count != aux_count) {
#if M_OSXFUSE_ENABLE_UNSUPPORTED
                        const char *vname = vnode_getname(vp);
                        IOLog("osxfuse: vnode reclaimed with valid fufh "
                              "(%s type=%d, vtype=%d, open_count=%d, busy=%d, "
                              "aux_count=%d)\n",
                              (vname) ? vname : "?", type, vnode_vtype(vp),
                              open_count, vnode_isinuse(vp, 0), aux_count);
                        if (vname) {
                            vnode_putname(vname);
                        }
#else
                        IOLog("osxfuse: vnode reclaimed with valid fufh "
                              "(type=%d, vtype=%d, open_count=%d, busy=%d, "
                              "aux_count=%d)\n",
                              type, vnode_vtype(vp), open_count,
                              vnode_isinuse(vp, 0), aux_count);
#endif /* M_OSXFUSE_ENABLE_UNSUPPORTED */
                    } /* if counts did not match (both=1 for match currently) */
                    FUSE_OSAddAtomic(1, (SInt32 *)&fuse_fh_zombies);
                } /* !deadfs */

                (void)fuse_filehandle_put(vp, context, type,
                                          FUSE_OP_FOREGROUNDED);

            } /* !forced unmount */
        } /* valid fufh */
    } /* fufh loop */

    if ((!fuse_isdeadfs(vp)) && (fvdat->nlookup)) {
        mount_t mp = vnode_mount(vp);
        struct fuse_data *data = fuse_get_mpdata(mp);
        struct fuse_dispatcher fdi;

        fdata_wait_init(data);
        fdisp_init(&fdi, 0);
        fuse_internal_forget_send(mp, context, VTOI(vp), fvdat->nlookup, &fdi);
        fuse_ticket_release(fdi.tick);
    }

    fuse_vncache_purge(vp);

    hn = HNodeFromVNode(vp);
    if (HNodeDetachVNode(hn, vp)) {
        FSNodeScrub(fvdat);
        HNodeScrubDone(hn);
        FUSE_OSAddAtomic(-1, (SInt32 *)&fuse_vnodes_current);
    }

    return 0;
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
fuse_vnop_remove(struct vnop_remove_args *ap)
{
    vnode_t               dvp     = ap->a_dvp;
    vnode_t               vp      = ap->a_vp;
    struct componentname *cnp     = ap->a_cnp;
    int                   flags   = ap->a_flags;
    vfs_context_t         context = ap->a_context;

    int err;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_fs(vp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(vp, context, ENOENT);

    if (vnode_isdir(vp)) {
        return EPERM;
    }

    /* Check for Carbon delete semantics. */
    if ((flags & VNODE_REMOVE_NODELETEBUSY) && vnode_isinuse(vp, 0)) {
        return EBUSY;
    }

    fuse_vncache_purge(vp);

    err = fuse_internal_remove(dvp, vp, cnp, FUSE_UNLINK, context);

    if (err == 0) {
        fuse_vncache_purge(vp);
        fuse_invalidate_attr(dvp);
        /*
         * If we really want, we could...
         * if (!vnode_isinuse(vp, 0)) {
         *     vnode_recycle(vp);
         * }
         */
    }

    return err;
}

#if M_OSXFUSE_ENABLE_XATTR
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
fuse_vnop_removexattr(struct vnop_removexattr_args *ap)
{
    vnode_t        vp      = ap->a_vp;
    const char    *name    = ap->a_name;
    vfs_context_t  context = ap->a_context;

    struct fuse_dispatcher fdi;
    struct fuse_data      *data;

    mount_t mp;
    size_t  namelen;

    int err = 0;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(vp, context, ENOENT);

    if (name == NULL || name[0] == '\0') {
        return EINVAL;  /* invalid name */
    }

    mp = vnode_mount(vp);
    data = fuse_get_mpdata(mp);

    if (fuse_skip_apple_xattr_mp(mp, name)) {
        return EPERM;
    }

    if (data->dataflags & FSESS_AUTO_XATTR) {
        return ENOTSUP;
    }

    if (!fuse_implemented(data, FSESS_NOIMPLBIT(REMOVEXATTR))) {
        return ENOTSUP;
    }

    namelen = strlen(name);

    fdisp_init(&fdi, namelen + 1);
    fdisp_make_vp(&fdi, FUSE_REMOVEXATTR, vp, context);

    memcpy((char *)fdi.indata, name, namelen);
    ((char *)fdi.indata)[namelen] = '\0';

    err = fdisp_wait_answ(&fdi);
    if (!err) {
        fuse_ticket_release(fdi.tick);
        VTOFUD(vp)->c_flag |= C_TOUCH_CHGTIME;
        fuse_invalidate_attr(vp);
    } else {
        if (err == ENOSYS) {
            fuse_clear_implemented(data, FSESS_NOIMPLBIT(REMOVEXATTR));
            return ENOTSUP;
        }
    }

    return err;
}
#endif /* M_OSXFUSE_ENABLE_XATTR */

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
fuse_vnop_rename(struct vnop_rename_args *ap)
{
    vnode_t fdvp               = ap->a_fdvp;
    vnode_t fvp                = ap->a_fvp;
    struct componentname *fcnp = ap->a_fcnp;
    vnode_t tdvp               = ap->a_tdvp;
    vnode_t tvp                = ap->a_tvp;
    struct componentname *tcnp = ap->a_tcnp;
    vfs_context_t context      = ap->a_context;

    int err = 0;

    fuse_trace_printf_vnop_novp();

    if (fuse_isdeadfs_fs(fdvp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(fdvp, context, ENOENT);

    fuse_vncache_purge(fvp);

    err = fuse_internal_rename(fdvp, fvp, fcnp, tdvp, tvp, tcnp, ap->a_context);

    if (err == 0) {
        fuse_invalidate_attr(fdvp);
        if (tdvp != fdvp) {
            fuse_invalidate_attr(tdvp);
        }
    }

    if (tvp != NULLVP) {
        if (tvp != fvp) {
            fuse_vncache_purge(tvp);
        }
        if (err == 0) {

            /*
             * If we want the file to just "disappear" from the standpoint
             * of those who might have it open, we can do a revoke/recycle
             * here. Otherwise, don't do anything. Only doing a recycle will
             * make our fufh-checking code in reclaim unhappy, leading us to
             * proactively panic.
             */

            /*
             * 1. revoke
             * 2. recycle
             */
        }
    }

    if (vnode_isdir(fvp)) {
        if ((tvp != NULLVP) && vnode_isdir(tvp)) {
            fuse_vncache_purge(tdvp);
        }
        fuse_vncache_purge(fdvp);
    }

    return err;
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
fuse_vnop_revoke(struct vnop_revoke_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    vfs_context_t context = ap->a_context;

    fuse_trace_printf_vnop();

    CHECK_BLANKET_DENIAL(vp, context, ENOENT);

    return fuse_internal_revoke(ap->a_vp, ap->a_flags, ap->a_context, 1);
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
fuse_vnop_rmdir(struct vnop_rmdir_args *ap)
{
    vnode_t               dvp     = ap->a_dvp;
    vnode_t               vp      = ap->a_vp;
    struct componentname *cnp     = ap->a_cnp;
    vfs_context_t         context = ap->a_context;

    int err;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs_fs(vp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(vp, context, ENOENT);

    if (VTOFUD(vp) == VTOFUD(dvp)) {
        return EINVAL;
    }

    fuse_vncache_purge(vp);

    err = fuse_internal_remove(dvp, vp, cnp, FUSE_RMDIR, context);

    if (err == 0) {
        fuse_invalidate_attr(dvp);
    }

    return err;
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
fuse_vnop_select(__unused struct vnop_select_args *ap)
{
    fuse_trace_printf_vnop_novp();

    return 1;
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
fuse_vnop_setattr(struct vnop_setattr_args *ap)
{
    vnode_t            vp      = ap->a_vp;
    struct vnode_attr *vap     = ap->a_vap;
    vfs_context_t      context = ap->a_context;

    struct fuse_data       *data;
    struct fuse_dispatcher  fdi;
    struct fuse_abi_data    fsai;
    struct fuse_abi_data    fao;
    struct fuse_abi_data    fa;

    int err = 0;
    enum vtype vtyp;
    int sizechanged = 0;
    uint64_t newsize = 0;

    fuse_trace_printf_vnop();

    /*
     * XXX: Locking
     *
     * We need to worry about the file size changing in setattr(). If the call
     * is indeed altering the size, then:
     *
     * lock_exclusive(truncatelock)
     *   lock(nodelock)
     *     set the new size
     *   unlock(nodelock)
     *   adjust ubc
     *   lock(nodelock)
     *     do cleanup
     *   unlock(nodelock)
     * unlock(truncatelock)
     * ...
     */

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(vp, context, ENOENT);

    data = fuse_get_mpdata(vnode_mount(vp));

    fdisp_init_abi(&fdi, fuse_setattr_in, data);
    fdisp_make_vp(&fdi, FUSE_SETATTR, vp, context);
    fuse_abi_data_init(&fsai, DATOI(data), fdi.indata);

    sizechanged = fuse_internal_attr_vat2fsai(vnode_mount(vp), vp, vap,
                                              &fsai, &newsize);

    if (!fuse_setattr_in_get_valid(&fsai)) {
        goto out;
    }

    vtyp = vnode_vtype(vp);

    if (fuse_setattr_in_get_valid(&fsai) & FATTR_SIZE && vtyp == VDIR) {
        err = EISDIR;
        goto out;
    }

    if (vnode_vfsisrdonly(vp) &&
        (fuse_setattr_in_get_valid(&fsai) & ~FATTR_SIZE || vtyp == VREG)) {
        err = EROFS;
        goto out;
    }


    err = fdisp_wait_answ(&fdi);
    if (err) {
        fuse_invalidate_attr(vp);
        return err;
    }

    fuse_abi_data_init(&fao, DATOI(data), fdi.answ);
    fuse_abi_data_init(&fa, fao.fad_version, fuse_attr_out_get_attr(&fao));

    vtyp = IFTOVT(fuse_attr_get_mode(&fa));

    if (vnode_vtype(vp) != vtyp) {
        if ((vnode_vtype(vp) == VNON) && (vtyp != VNON)) {
            /* What just happened here? */
        } else {

            /*
             * STALE vnode, ditch
             *
             * The vnode has changed its type "behind our back". There's
             * nothing really we can do, so let us just force an internal
             * revocation and tell the caller to try again, if interested.
             */

#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(data->biglock);
#endif
            fuse_internal_vnode_disappear(vp, context, REVOKE_SOFT);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(data->biglock);
#endif

            err = EAGAIN;
        }
    }

    if (!err) {
        if (sizechanged) {
            fuse_invalidate_attr(vp);
        } else {
            cache_attrs(vp, fuse_attr_out, &fao);
            if (fuse_setattr_in_get_valid(&fsai) & FATTR_BKUPTIME ||
                fuse_setattr_in_get_valid(&fsai) & FATTR_CRTIME) {
                VTOFUD(vp)->c_flag &= ~C_XTIMES_VALID;
            }
        }
    }

    fuse_ticket_release(fdi.tick);

out:
    if (!err && sizechanged) {
        VTOFUD(vp)->filesize = newsize;
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_unlock(data->biglock);
#endif
        ubc_setsize(vp, (off_t)newsize);
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_lock(data->biglock);
#endif
    }

    return err;
}

#if M_OSXFUSE_ENABLE_XATTR
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
fuse_vnop_setxattr(struct vnop_setxattr_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    const char   *name    = ap->a_name;
    uio_t         uio     = ap->a_uio;
    vfs_context_t context = ap->a_context;

    struct fuse_dispatcher  fdi;
    struct fuse_abi_data    fsxi;
    struct fuse_data       *data;

    user_addr_t a_baseaddr[FUSE_UIO_BACKUP_MAX];
    user_size_t a_length[FUSE_UIO_BACKUP_MAX];

    mount_t mp;

    int err = 0;
    int iov_err = 0;
    int i, iov_cnt;
    size_t namelen;
    size_t attrsize;
    off_t  saved_offset;
    void *next;

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(vp, context, ENOENT);

    if (name == NULL || name[0] == '\0') {
        return EINVAL;
    }

    mp = vnode_mount(vp);
    data = fuse_get_mpdata(mp);

    if (fuse_skip_apple_xattr_mp(mp, name)) {
        return EPERM;
    }

    if (data->dataflags & FSESS_AUTO_XATTR) {
        return ENOTSUP;
    }

    if (!fuse_implemented(data, FSESS_NOIMPLBIT(SETXATTR))) {
        return ENOTSUP;
    }

    attrsize = (size_t)uio_resid(uio);
    saved_offset = uio_offset(uio);

    iov_cnt = uio_iovcnt(uio);
    if (iov_cnt > FUSE_UIO_BACKUP_MAX) {
        /* no need to make it more complicated */
        iov_cnt = FUSE_UIO_BACKUP_MAX;
    }

    for (i = 0; i < iov_cnt; i++) {
        iov_err = uio_getiov(uio, i, &(a_baseaddr[i]), &(a_length[i]));
    }

    /*
     * Check attrsize for some sane maximum: otherwise, we can fail malloc()
     * in fdisp_make_vp().
     */
    if (attrsize > data->userkernel_bufsize) {
        return E2BIG;
    }

    namelen = strlen(name);

    fdata_wait_init(data);
    fdisp_init(&fdi, fuse_setxattr_in_sizeof(DATOI(data)) +
                     namelen + 1 + attrsize);
    err = fdisp_make_vp_canfail(&fdi, FUSE_SETXATTR, vp, ap->a_context);
    if (err) {
        IOLog("osxfuse: setxattr failed for too large attribute (%lu)\n",
              attrsize);
        return ERANGE;
    }

    fuse_abi_data_init(&fsxi, DATOI(data), fdi.indata);
    next = (char *)fdi.indata + fuse_setxattr_in_sizeof(DATOI(data));

    fuse_setxattr_in_set_size(&fsxi, (uint32_t)attrsize);
    fuse_setxattr_in_set_flags(&fsxi, ap->a_options);
    fuse_setxattr_in_set_position(&fsxi, (uint32_t)saved_offset);

    if (attrsize > FUSE_REASONABLE_XATTRSIZE) {
        fticket_set_kill(fdi.tick);
    }

    memcpy(next, name, namelen);
    ((char *)next)[namelen] = '\0';

#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_unlock(data->biglock);
#endif
    err = uiomove((char *)next + namelen + 1, (int)attrsize, uio);
#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_lock(data->biglock);
#endif
    if (!err) {
        err = fdisp_wait_answ(&fdi);
    }

    if (!err) {
        fuse_ticket_release(fdi.tick);
        fuse_invalidate_attr(vp);
        VTOFUD(vp)->c_flag |= C_TOUCH_CHGTIME;
    } else {
        if ((err == ENOSYS) || (err == ENOTSUP)) {

            int a_spacetype = UIO_USERSPACE;

            if (err == ENOSYS) {
                fuse_clear_implemented(data, FSESS_NOIMPLBIT(SETXATTR));
            }

            if (iov_err) {
                return EAGAIN;
            }

            if (!uio_isuserspace(uio)) {
                a_spacetype = UIO_SYSSPACE;
            }

            uio_reset(uio, saved_offset, a_spacetype, uio_rw(uio));
            for (i = 0; i < iov_cnt; i++) {
                uio_addiov(uio, CAST_USER_ADDR_T(a_baseaddr[i]), a_length[i]);
            }

            return ENOTSUP;
        }
    }

    return err;
}
#endif /* M_OSXFUSE_ENABLE_XATTR */

/*
    struct vnop_strategy_args {
        struct vnodeop_desc *a_desc;
        struct buf          *a_bp;
    };
*/
FUSE_VNOP_EXPORT
int
fuse_vnop_strategy(struct vnop_strategy_args *ap)
{
    buf_t   bp = ap->a_bp;
    vnode_t vp = buf_vnode(bp);

    fuse_trace_printf_vnop();

    if (!vp || fuse_isdeadfs(vp)) {
        buf_seterror(bp, EIO);
        buf_biodone(bp);
        return ENXIO;
    }

    return fuse_internal_strategy_buf(ap);
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
fuse_vnop_symlink(struct vnop_symlink_args *ap)
{
    vnode_t               dvp     = ap->a_dvp;
    vnode_t              *vpp     = ap->a_vpp;
    struct componentname *cnp     = ap->a_cnp;
    char                 *target  = ap->a_target;
    vfs_context_t         context = ap->a_context;

    struct fuse_dispatcher fdi;

    int err;
    size_t len;

    fuse_trace_printf_vnop_novp();

    if (fuse_isdeadfs_fs(dvp)) {
        return ENXIO;
    }

    CHECK_BLANKET_DENIAL(dvp, context, EPERM);

    len = strlen(target) + 1;
    fdisp_init(&fdi, len + cnp->cn_namelen + 1);
    fdisp_make_vp(&fdi, FUSE_SYMLINK, dvp, context);

    memcpy(fdi.indata, cnp->cn_nameptr, cnp->cn_namelen);
    ((char *)fdi.indata)[cnp->cn_namelen] = '\0';
    memcpy((char *)fdi.indata + cnp->cn_namelen + 1, target, len);

    /* XXX: Need to take vap into account. */

    /* Note: fuse_internal_newentry_core releases fdi.tick */
    err = fuse_internal_newentry_core(dvp, vpp, cnp, VLNK, &fdi, context);

    if (err == 0) {
        fuse_invalidate_attr(dvp);
    }

    return err;
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
fuse_vnop_write(struct vnop_write_args *ap)
{
    vnode_t       vp      = ap->a_vp;
    uio_t         uio     = ap->a_uio;
    int           ioflag  = ap->a_ioflag;
    vfs_context_t context = ap->a_context;

    int          error = 0;
    int          lflag;
    off_t        offset;
    off_t        zero_off;
    off_t        filesize;
    off_t        original_offset;
    off_t        original_size;
    user_ssize_t original_resid;

    struct fuse_vnode_data *fvdat;

    /*
     * XXX: Locking
     *
     * lock_shared(truncatelock)
     * lock(nodelock)
     * if (file is being extended) {
     *     unlock(nodelock)
     *     unlock(truncatelock)
     *     lock_exclusive(truncatelock)
     *     lock(nodelock)
     *     current_size = the file's current size
     * }
     * if (file is being extended) { // check again
     *     // do whatever needs to be done to allocate storage
     * }
     * // We are always block-aligned
     * unlock(nodelock)
     * call the cluster layer
     * adjust ubc
     * lock(nodelock)
     * do cleanup
     * unlock(nodelock)
     * unlock(truncatelock)
     */

    fuse_trace_printf_vnop();

    if (fuse_isdeadfs(vp) && !vnode_isinuse(vp, 0)) {
        return ENXIO;
    }

    fvdat = VTOFUD(vp);

    switch (vnode_vtype(vp)) {
    case VREG:
        break;

    case VDIR:
        return EISDIR;

    default:
        return EPERM; /* or EINVAL? panic? */
    }

    original_resid = uio_resid(uio);
    original_offset = uio_offset(uio);
    offset = original_offset;

    if (original_resid == 0) {
        return 0;
    }

    if (original_offset < 0) {
        return EINVAL;
    }

    if (fuse_isdirectio(vp)) { /* direct_io */
        fufh_type_t             fufh_type = FUFH_WRONLY;
        struct fuse_data       *data;
        struct fuse_dispatcher  fdi;
        struct fuse_filehandle *fufh = NULL;
        struct fuse_abi_data    fwi;
        struct fuse_abi_data    fwo;

        size_t chunksize;
        off_t  diff;
        void *next;

        data = fuse_get_mpdata(vnode_mount(vp));

        fufh = &(fvdat->fufh[fufh_type]);

        if (!FUFH_IS_VALID(fufh)) {
            fufh_type = FUFH_RDWR;
            fufh = &(fvdat->fufh[fufh_type]);
            if (!FUFH_IS_VALID(fufh)) {
                fufh = NULL;
            } else {
                /* Write falling back to FUFH_RDWR. */
            }
        }

        if (!fufh) {
            /* Failing direct I/O because of no fufh. */
            return EIO;
        } else {
            /* Using existing fufh of type fufh_type. */
        }

        fdata_wait_init(data);
        fdisp_init(&fdi, 0);

        while (uio_resid(uio) > 0) {
            chunksize = min((size_t)uio_resid(uio), VTOVA(vp)->va_iosize);

            fdi.iosize = fuse_write_in_sizeof(DATOI(data)) +
                         chunksize;
            fdisp_make_vp(&fdi, FUSE_WRITE, vp, context);
            fuse_abi_data_init(&fwi, DATOI(data), fdi.indata);
            next = (char *)fdi.indata + fuse_write_in_sizeof(DATOI(data));

            fuse_write_in_set_fh(&fwi, fufh->fh_id);
            fuse_write_in_set_offset(&fwi, uio_offset(uio));
            fuse_write_in_set_size(&fwi, (uint32_t)chunksize);
            fuse_write_in_set_flags(&fwi, 0);

#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(data->biglock);
#endif
            error = uiomove(next, (int)chunksize, uio);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(data->biglock);
#endif
            if (error) {
                break;
            }

            error = fdisp_wait_answ(&fdi);
            if (error) {
                return error;
            }

            fuse_abi_data_init(&fwo, DATOI(data), fdi.answ);
            diff = chunksize - fuse_write_out_get_size(&fwo);

            if (diff < 0) {
                error = EINVAL;
                break;

            } else if (diff > 0) {
                /*
                 * The write operation could not be fully executed.
                 *
                 * Note that merely resetting the residue and offset leaves the
                 * uio in an inconsistent state, since the iov-related fields
                 * are not correspondingly adjusted.
                 *
                 * Further uses of uiomove() in this state are illegal.
                 */
                uio_setresid(uio, uio_resid(uio) + diff);
                uio_setoffset(uio, uio_offset(uio) - diff);

                break;
            }

        } /* while */

        if (!error) {
            fuse_invalidate_attr(vp);
        }

        if (fdi.tick) {
            fuse_ticket_release(fdi.tick);
        }

        return error;

    } /* direct_io */

    /* !direct_io */

    /* Be wary of a size change here. */

    original_size = fvdat->filesize;

    if (ioflag & IO_APPEND) {
        /* Arrange for append */
        uio_setoffset(uio, fvdat->filesize);
        offset = fvdat->filesize;
    }

    if (offset < 0) {
        return EFBIG;
    }

#if M_OSXFUSE_EXPERIMENTAL_JUNK
    if (original_resid == 0) {
        return 0;
    }

    if (offset + original_resid > /* some maximum file size */) {
        return EFBIG;
    }
#endif

    if (offset + original_resid > original_size) {
        /* Need to extend the file. */
        filesize = offset + original_resid;
        fvdat->filesize = filesize;
    } else {
        /* Original size OK. */
        filesize = original_size;
    }

    lflag = (ioflag & (IO_SYNC | IO_NOCACHE));

    if (fuse_isnoubc(vp)) {
        lflag |= (IO_SYNC | IO_NOCACHE);
    } else if (vfs_issynchronous(vnode_mount(vp))) {
        lflag |= IO_SYNC;
    }

    if (offset > original_size) {
        zero_off = original_size;
        lflag |= IO_HEADZEROFILL;
        /* Zero-filling enabled. */
    } else {
        zero_off = 0;
    }

#if M_OSXFUSE_ENABLE_BIG_LOCK
    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));
    fuse_biglock_unlock(data->biglock);
#endif
    error = cluster_write(vp, uio, (off_t)original_size, (off_t)filesize,
                          (off_t)zero_off, (off_t)0, lflag);
#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_lock(data->biglock);
#endif

    if (!error) {
        if (uio_offset(uio) > original_size) {
            /* Updating to new size. */
            fvdat->filesize = uio_offset(uio);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(data->biglock);
#endif
            ubc_setsize(vp, (off_t)fvdat->filesize);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(data->biglock);
#endif
        } else {
            fvdat->filesize = original_size;
        }
        fuse_invalidate_attr(vp);
    }

    /*
     * If original_resid > uio_resid(uio), we could set an internal
     * flag bit to "update" (e.g., dep->de_flag |= DE_UPDATE).
     */

    /*
     * If the write failed and they want us to, truncate the file back
     * to the size it was before the write was attempted.
     */

/* errexit: */

    if (error) {
        if (ioflag & IO_UNIT) {
            /*
             * e.g.: detrunc(dep, original_size, ioflag & IO_SYNC, context);
             */
            uio_setoffset(uio, original_offset);
            uio_setresid(uio, original_resid);
        } else {
            /*
             * e.g.: detrunc(dep, dep->de_FileSize, ioflag & IO_SYNC, context);
             */
            if (uio_resid(uio) != original_resid) {
                error = 0;
            }
        }
    } else if (ioflag & IO_SYNC) {
        /*
         * e.g.: error = deupdat(dep, 1, context);
         */
    }

    /*
    if ((original_resid > uio_resid(uio)) &&
        !fuse_vfs_context_issuser(context)) {
        // clear setuid/setgid here
    }
     */

    return error;
}

#if M_OSXFUSE_ENABLE_FIFOFS

/* fifofs */

FUSE_VNOP_EXPORT
int
fuse_fifo_vnop_close(struct vnop_close_args *ap)
{
    if (vnode_isinuse(ap->a_vp, 1)) {
        /* XXX: TBD */
    }

    return fifo_close(ap);
}

FUSE_VNOP_EXPORT
int
fuse_fifo_vnop_read(struct vnop_read_args *ap)
{
    VTOFUD(ap->a_vp)->c_flag |= C_TOUCH_ACCTIME;

    return fifo_read(ap);
}

FUSE_VNOP_EXPORT
int
fuse_fifo_vnop_write(struct vnop_write_args *ap)
{
    VTOFUD(ap->a_vp)->c_flag |= (C_TOUCH_CHGTIME | C_TOUCH_MODTIME);

    return fifo_write(ap);
}

#endif /* M_OSXFUSE_ENABLE_FIFOFS */

#if M_OSXFUSE_ENABLE_SPECFS

/* specfs */

FUSE_VNOP_EXPORT
int
fuse_spec_vnop_close(struct vnop_close_args *ap)
{
    if (vnode_isinuse(ap->a_vp, 1)) {
        /* XXX: TBD */
    }

    return spec_close(ap);
}

FUSE_VNOP_EXPORT
int
fuse_spec_vnop_read(struct vnop_read_args *ap)
{
    VTOFUD(ap->a_vp)->c_flag |= C_TOUCH_ACCTIME;

    return spec_read(ap);
}

FUSE_VNOP_EXPORT
int
fuse_spec_vnop_write(struct vnop_write_args *ap)
{
    VTOFUD(ap->a_vp)->c_flag |= (C_TOUCH_CHGTIME | C_TOUCH_MODTIME);

    return spec_write(ap);
}

#endif /* M_OSXFUSE_ENABLE_SPECFS */

struct vnodeopv_entry_desc fuse_vnode_operation_entries[] = {
    { &vnop_access_desc,        (fuse_vnode_op_t) fuse_vnop_access        },
    { &vnop_advlock_desc,       (fuse_vnode_op_t) err_advlock             },
    { &vnop_allocate_desc,      (fuse_vnode_op_t) fuse_vnop_allocate      },
    { &vnop_blktooff_desc,      (fuse_vnode_op_t) fuse_vnop_blktooff      },
    { &vnop_blockmap_desc,      (fuse_vnode_op_t) fuse_vnop_blockmap      },
//  { &vnop_bwrite_desc,        (fuse_vnode_op_t) fuse_vnop_bwrite        },
    { &vnop_close_desc,         (fuse_vnode_op_t) fuse_vnop_close         },
//  { &vnop_copyfile_desc,      (fuse_vnode_op_t) fuse_vnop_copyfile      },
    { &vnop_create_desc,        (fuse_vnode_op_t) fuse_vnop_create        },
    { &vnop_default_desc,       (fuse_vnode_op_t) vn_default_error        },
    { &vnop_exchange_desc,      (fuse_vnode_op_t) fuse_vnop_exchange      },
    { &vnop_fsync_desc,         (fuse_vnode_op_t) fuse_vnop_fsync         },
    { &vnop_getattr_desc,       (fuse_vnode_op_t) fuse_vnop_getattr       },
//  { &vnop_getattrlist_desc,   (fuse_vnode_op_t) fuse_vnop_getattrlist   },
#if M_OSXFUSE_ENABLE_XATTR
    { &vnop_getxattr_desc,      (fuse_vnode_op_t) fuse_vnop_getxattr      },
#endif /* M_OSXFUSE_ENABLE_XATTR */
    { &vnop_inactive_desc,      (fuse_vnode_op_t) fuse_vnop_inactive      },
    { &vnop_ioctl_desc,         (fuse_vnode_op_t) fuse_vnop_ioctl         },
    { &vnop_link_desc,          (fuse_vnode_op_t) fuse_vnop_link          },
#if M_OSXFUSE_ENABLE_XATTR
    { &vnop_listxattr_desc,     (fuse_vnode_op_t) fuse_vnop_listxattr     },
#endif /* M_OSXFUSE_ENABLE_XATTR */
    { &vnop_lookup_desc,        (fuse_vnode_op_t) fuse_vnop_lookup        },
#if M_OSXFUSE_ENABLE_KQUEUE
    { &vnop_kqfilt_add_desc,    (fuse_vnode_op_t) fuse_vnop_kqfilt_add    },
    { &vnop_kqfilt_remove_desc, (fuse_vnode_op_t) fuse_vnop_kqfilt_remove },
#endif /* M_OSXFUSE_ENABLE_KQUEUE */
    { &vnop_mkdir_desc,         (fuse_vnode_op_t) fuse_vnop_mkdir         },
    { &vnop_mknod_desc,         (fuse_vnode_op_t) fuse_vnop_mknod         },
    { &vnop_mmap_desc,          (fuse_vnode_op_t) fuse_vnop_mmap          },
    { &vnop_mnomap_desc,        (fuse_vnode_op_t) fuse_vnop_mnomap        },
    { &vnop_offtoblk_desc,      (fuse_vnode_op_t) fuse_vnop_offtoblk      },
    { &vnop_open_desc,          (fuse_vnode_op_t) fuse_vnop_open          },
    { &vnop_pagein_desc,        (fuse_vnode_op_t) fuse_vnop_pagein        },
    { &vnop_pageout_desc,       (fuse_vnode_op_t) fuse_vnop_pageout       },
    { &vnop_pathconf_desc,      (fuse_vnode_op_t) fuse_vnop_pathconf      },
    { &vnop_read_desc,          (fuse_vnode_op_t) fuse_vnop_read          },
    { &vnop_readdir_desc,       (fuse_vnode_op_t) fuse_vnop_readdir       },
//  { &vnop_readdirattr_desc,   (fuse_vnode_op_t) fuse_vnop_readdirattr   },
    { &vnop_readlink_desc,      (fuse_vnode_op_t) fuse_vnop_readlink      },
    { &vnop_reclaim_desc,       (fuse_vnode_op_t) fuse_vnop_reclaim       },
    { &vnop_remove_desc,        (fuse_vnode_op_t) fuse_vnop_remove        },
#if M_OSXFUSE_ENABLE_XATTR
    { &vnop_removexattr_desc,   (fuse_vnode_op_t) fuse_vnop_removexattr   },
#endif /* M_OSXFUSE_ENABLE_XATTR */
    { &vnop_rename_desc,        (fuse_vnode_op_t) fuse_vnop_rename        },
    { &vnop_revoke_desc,        (fuse_vnode_op_t) fuse_vnop_revoke        },
    { &vnop_rmdir_desc,         (fuse_vnode_op_t) fuse_vnop_rmdir         },
//  { &vnop_searchfs_desc,      (fuse_vnode_op_t) fuse_vnop_searchfs      },
    { &vnop_select_desc,        (fuse_vnode_op_t) fuse_vnop_select        },
    { &vnop_setattr_desc,       (fuse_vnode_op_t) fuse_vnop_setattr       },
//  { &vnop_setattrlist_desc,   (fuse_vnode_op_t) fuse_vnop_setattrlist   },
#if M_OSXFUSE_ENABLE_XATTR
    { &vnop_setxattr_desc,      (fuse_vnode_op_t) fuse_vnop_setxattr      },
#endif /* M_OSXFUSE_ENABLE_XATTR */
    { &vnop_strategy_desc,      (fuse_vnode_op_t) fuse_vnop_strategy      },
    { &vnop_symlink_desc,       (fuse_vnode_op_t) fuse_vnop_symlink       },
//  { &vnop_whiteout_desc,      (fuse_vnode_op_t) fuse_vnop_whiteout      },
    { &vnop_write_desc,         (fuse_vnode_op_t) fuse_vnop_write         },
    { NULL, NULL }
};

#if M_OSXFUSE_ENABLE_FIFOFS

/* fifofs */

struct vnodeopv_entry_desc fuse_fifo_operation_entries[] = {
    { &vnop_advlock_desc,       (fuse_fifo_op_t)err_advlock             },
    { &vnop_blktooff_desc,      (fuse_fifo_op_t)err_blktooff            },
    { &vnop_blockmap_desc,      (fuse_fifo_op_t)err_blockmap            },
    { &vnop_bwrite_desc,        (fuse_fifo_op_t)fifo_bwrite             },
    { &vnop_close_desc,         (fuse_fifo_op_t)fuse_fifo_vnop_close    }, // c
    { &vnop_copyfile_desc,      (fuse_fifo_op_t)err_copyfile            },
    { &vnop_create_desc,        (fuse_fifo_op_t)fifo_create             },
    { &vnop_default_desc,       (fuse_fifo_op_t)vn_default_error        },
    { &vnop_fsync_desc,         (fuse_fifo_op_t)fuse_vnop_fsync         },
    { &vnop_getattr_desc,       (fuse_fifo_op_t)fuse_vnop_getattr       },
    { &vnop_inactive_desc,      (fuse_fifo_op_t)fuse_vnop_inactive      },
    { &vnop_ioctl_desc,         (fuse_fifo_op_t)fifo_ioctl              },
#if M_OSXFUSE_ENABLE_KQUEUE
    { &vnop_kqfilt_add_desc,    (fuse_fifo_op_t)fuse_vnop_kqfilt_add    },
    { &vnop_kqfilt_remove_desc, (fuse_fifo_op_t)fuse_vnop_kqfilt_remove },
#endif
    { &vnop_link_desc,          (fuse_fifo_op_t)fifo_link               },
    { &vnop_lookup_desc,        (fuse_fifo_op_t)fifo_lookup             },
    { &vnop_mkdir_desc,         (fuse_fifo_op_t)fifo_mkdir              },
    { &vnop_mknod_desc,         (fuse_fifo_op_t)fifo_mknod              },
    { &vnop_mmap_desc,          (fuse_fifo_op_t)fifo_mmap               },
    { &vnop_offtoblk_desc,      (fuse_fifo_op_t)err_offtoblk            },
    { &vnop_open_desc,          (fuse_fifo_op_t)fifo_open               },
    { &vnop_pagein_desc,        (fuse_fifo_op_t)fuse_vnop_pagein        }, // n
    { &vnop_pageout_desc,       (fuse_fifo_op_t)fuse_vnop_pageout       }, // n
    { &vnop_pathconf_desc,      (fuse_fifo_op_t)fifo_pathconf           },
    { &vnop_read_desc,          (fuse_fifo_op_t)fuse_fifo_vnop_read     }, // c
    { &vnop_readdir_desc,       (fuse_fifo_op_t)fifo_readdir            },
    { &vnop_readlink_desc,      (fuse_fifo_op_t)fifo_readlink           },
    { &vnop_reclaim_desc,       (fuse_fifo_op_t)fuse_vnop_reclaim       }, // n
    { &vnop_remove_desc,        (fuse_fifo_op_t)fifo_remove             },
    { &vnop_rename_desc,        (fuse_fifo_op_t)fifo_rename             },
    { &vnop_revoke_desc,        (fuse_fifo_op_t)fifo_revoke             },
    { &vnop_rmdir_desc,         (fuse_fifo_op_t)fifo_rmdir              },
    { &vnop_select_desc,        (fuse_fifo_op_t)fifo_select             },
    { &vnop_setattr_desc,       (fuse_fifo_op_t)fuse_vnop_setattr       }, // n
    { &vnop_strategy_desc,      (fuse_fifo_op_t)fifo_strategy           },
    { &vnop_symlink_desc,       (fuse_fifo_op_t)fifo_symlink            },
    { &vnop_write_desc,         (fuse_fifo_op_t)fuse_fifo_vnop_write    },
    { (struct vnodeop_desc*)NULL, (fuse_fifo_op_t)NULL                  }
};
#endif /* M_OSXFUSE_ENABLE_FIFOFS */

#if M_OSXFUSE_ENABLE_SPECFS

/* specfs */

struct vnodeopv_entry_desc fuse_spec_operation_entries[] = {
    { &vnop_advlock_desc,  (fuse_spec_op_t)err_advlock          },
    { &vnop_blktooff_desc, (fuse_spec_op_t)fuse_vnop_blktooff   }, // native
    { &vnop_close_desc,    (fuse_spec_op_t)fuse_spec_vnop_close }, // custom
    { &vnop_copyfile_desc, (fuse_spec_op_t)err_copyfile         },
    { &vnop_create_desc,   (fuse_spec_op_t)spec_create          },
    { &vnop_default_desc,  (fuse_spec_op_t)vn_default_error     },
    { &vnop_fsync_desc,    (fuse_spec_op_t)fuse_vnop_fsync      }, // native
    { &vnop_getattr_desc,  (fuse_spec_op_t)fuse_vnop_getattr    }, // native
    { &vnop_inactive_desc, (fuse_spec_op_t)fuse_vnop_inactive   }, // native
    { &vnop_ioctl_desc,    (fuse_spec_op_t)spec_ioctl           },
    { &vnop_link_desc,     (fuse_spec_op_t)spec_link            },
    { &vnop_lookup_desc,   (fuse_spec_op_t)spec_lookup          },
    { &vnop_mkdir_desc,    (fuse_spec_op_t)spec_mkdir           },
    { &vnop_mknod_desc,    (fuse_spec_op_t)spec_mknod           },
    { &vnop_mmap_desc,     (fuse_spec_op_t)spec_mmap            },
    { &vnop_offtoblk_desc, (fuse_spec_op_t)fuse_vnop_offtoblk   }, // native
    { &vnop_open_desc,     (fuse_spec_op_t)spec_open            },
    { &vnop_pagein_desc,   (fuse_spec_op_t)fuse_vnop_pagein     }, // native
    { &vnop_pageout_desc,  (fuse_spec_op_t)fuse_vnop_pageout    }, // native
    { &vnop_pathconf_desc, (fuse_spec_op_t)spec_pathconf        },
    { &vnop_read_desc,     (fuse_spec_op_t)fuse_spec_vnop_read  }, // custom
    { &vnop_readdir_desc,  (fuse_spec_op_t)spec_readdir         },
    { &vnop_readlink_desc, (fuse_spec_op_t)spec_readlink        },
    { &vnop_reclaim_desc,  (fuse_spec_op_t)fuse_vnop_reclaim    }, // native
    { &vnop_remove_desc,   (fuse_spec_op_t)spec_remove          },
    { &vnop_rename_desc,   (fuse_spec_op_t)spec_rename          },
    { &vnop_revoke_desc,   (fuse_spec_op_t)spec_revoke          },
    { &vnop_rmdir_desc,    (fuse_spec_op_t)spec_rmdir           },
    { &vnop_select_desc,   (fuse_spec_op_t)spec_select          },
    { &vnop_setattr_desc,  (fuse_spec_op_t)fuse_vnop_setattr    }, // native
    { &vnop_strategy_desc, (fuse_spec_op_t)spec_strategy        },
    { &vnop_symlink_desc,  (fuse_spec_op_t)spec_symlink         },
    { &vnop_write_desc,    (fuse_spec_op_t)fuse_spec_vnop_write }, // custom
    { (struct vnodeop_desc*)NULL, (fuse_spec_op_t)NULL          },
};
#endif /* M_OSXFUSE_ENABLE_SPECFS */
