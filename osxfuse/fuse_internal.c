/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2010 Tuxera Inc.
 * Copyright (c) 2011-2012 Anatol Pomozov
 * Copyright (c) 2011-2017 Benjamin Fleischer
 * All rights reserved.
 */

#include "fuse_internal.h"

#include "fuse_ipc.h"
#include "fuse_kludges.h"
#include "fuse_locking.h"
#include "fuse_node.h"

#if M_OSXFUSE_ENABLE_BIG_LOCK
#  include "fuse_biglock_vnops.h"
#endif

#include <stdbool.h>

#include <AvailabilityMacros.h>

/* msleep */

__private_extern__
int
fuse_internal_msleep(void *chan, lck_mtx_t *mtx, int pri, const char *wmesg,
                     struct timespec *ts, __unused struct fuse_data *data)
{
    int ret;
#if M_OSXFUSE_ENABLE_BIG_LOCK
    bool biglock_locked = false;

    if (data != NULL && fuse_biglock_have_lock(data->biglock)) {
        biglock_locked = true;
        fuse_biglock_unlock(data->biglock);
    }
#endif
    ret = msleep(chan, mtx, pri, wmesg, ts);
#if M_OSXFUSE_ENABLE_BIG_LOCK
    if (biglock_locked) {
        fuse_biglock_lock(data->biglock);
    }
#endif

    return ret;
}

/* access */

__private_extern__
int
fuse_internal_access(vnode_t                   vp,
                     int                       action,
                     vfs_context_t             context)
{
    int err = 0;
    int default_error = ENOTSUP;
    uint32_t mask = 0;
    int dataflags;
    mount_t mp;
    struct fuse_dispatcher  fdi;
    struct fuse_abi_data    fai;
    struct fuse_data       *data;

    fuse_trace_printf_func();

    mp = vnode_mount(vp);

    data = fuse_get_mpdata(mp);
    dataflags = data->dataflags;

    /* Allow for now; let checks be handled inline later. */
    if (fuse_isdeferpermissions_mp(mp)) {
        return 0;
    }

    /*
     * (action & KAUTH_VNODE_GENERIC_WRITE_BITS) on a read-only file system
     * would have been handled by higher layers.
     */

    if (!fuse_implemented(data, FSESS_NOIMPLBIT(ACCESS))) {
        return default_error;
    }

    if (vnode_isvroot(vp) || fuse_vfs_context_issuser(context)) {
        /*
         * Note: Starting with OS X 10.11 DesktopServicesHelper (which is
         * running as root) calls access(2) on behalf of Finder when trying to
         * delete a directory. Returning EPERM results in Finder aborting the
         * delete process. Therefore we are no longer blocking calls by root
         * even if allow_root and allow_other are not set.
         */
    } else {
        CHECK_BLANKET_DENIAL(vp, context, EPERM);
    }

    if (vnode_isdir(vp)) {
        if (action & (KAUTH_VNODE_LIST_DIRECTORY   |
                      KAUTH_VNODE_READ_EXTATTRIBUTES)) {
            mask |= R_OK;
        }
        if (action & (KAUTH_VNODE_ADD_FILE         |
                      KAUTH_VNODE_ADD_SUBDIRECTORY |
                      KAUTH_VNODE_DELETE_CHILD)) {
            mask |= W_OK;
        }
        if (action & KAUTH_VNODE_SEARCH) {
            mask |= X_OK;
        }
    } else {
        if (action & (KAUTH_VNODE_READ_DATA | KAUTH_VNODE_READ_EXTATTRIBUTES)) {
            mask |= R_OK;
        }
        if (action & (KAUTH_VNODE_WRITE_DATA | KAUTH_VNODE_APPEND_DATA)) {
            mask |= W_OK;
        }
        if (action & KAUTH_VNODE_EXECUTE) {
            mask |= X_OK;
        }
    }

    if (action & (KAUTH_VNODE_WRITE_ATTRIBUTES    |
                  KAUTH_VNODE_WRITE_EXTATTRIBUTES |
                  KAUTH_VNODE_WRITE_SECURITY)) {
        mask |= W_OK;
    }

    fdisp_init_abi(&fdi, fuse_access_in, data);
    fdisp_make_vp(&fdi, FUSE_ACCESS, vp, context);
    fuse_abi_data_init(&fai, DATOI(data), fdi.indata);

    fuse_access_in_set_mask(&fai, F_OK | mask);

    err = fdisp_wait_answ(&fdi);
    if (!err) {
        fuse_ticket_release(fdi.tick);
    }

    if (err == ENOSYS) {
        /*
         * Make sure we don't come in here again.
         */
        vfs_clearauthopaque(mp);
        fuse_clear_implemented(data, FSESS_NOIMPLBIT(ACCESS));
        err = default_error;
    }

    if (err == ENOENT) {

        const char *vname = NULL;

#if M_OSXFUSE_ENABLE_UNSUPPORTED
        vname = vnode_getname(vp);
#endif /* M_OSXFUSE_ENABLE_UNSUPPORTED */

        IOLog("osxfuse: disappearing vnode %p (name=%s type=%d action=%x)\n",
              vp, (vname) ? vname : "?", vnode_vtype(vp), action);

#if M_OSXFUSE_ENABLE_UNSUPPORTED
        if (vname) {
            vnode_putname(vname);
        }
#endif /* M_OSXFUSE_ENABLE_UNSUPPORTED */

        /*
         * On 10.4, I think I can get Finder to lock because of /.Trashes/<uid>
         * unless I use REVOKE_NONE here.
         */

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

#if M_OSXFUSE_ENABLE_EXCHANGE

/* exchange */

__private_extern__
int
fuse_internal_exchange(vnode_t       fvp,
                       const char   *fname,
                       size_t        flen,
                       vnode_t       tvp,
                       const char   *tname,
                       size_t        tlen,
                       int           options,
                       vfs_context_t context)
{
    struct fuse_data *data;
    struct fuse_dispatcher fdi;
    struct fuse_abi_data fei;
    struct fuse_vnode_data *ffud = VTOFUD(fvp);
    struct fuse_vnode_data *tfud = VTOFUD(tvp);
    vnode_t fdvp = ffud->parentvp;
    vnode_t tdvp = tfud->parentvp;
    void *next;
    int err = 0;

    data = fuse_get_mpdata(vnode_mount(fvp));

    fdata_wait_init(data);
    fdisp_init(&fdi, fuse_exchange_in_sizeof(DATOI(data)) + flen + tlen + 2);
    fdisp_make_vp(&fdi, FUSE_EXCHANGE, fvp, context);
    fuse_abi_data_init(&fei, DATOI(data), fdi.indata);

    fuse_exchange_in_set_olddir(&fei, VTOI(fdvp));
    fuse_exchange_in_set_newdir(&fei, VTOI(tdvp));
    fuse_exchange_in_set_options(&fei, (uint64_t)options);

    next = (char *)fdi.indata + fuse_exchange_in_sizeof(DATOI(data));

    memcpy(next, fname, flen);
    ((char *)next)[flen] = '\0';

    memcpy((char *)next + flen + 1, tname, tlen);
    ((char *)next)[flen + tlen + 1] = '\0';

#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_unlock(data->biglock);
#endif
    ubc_msync(fvp, (off_t)0, (off_t)ffud->filesize, NULL,
              UBC_PUSHALL | UBC_INVALIDATE | UBC_SYNC);
    ubc_msync(tvp, (off_t)0, (off_t)tfud->filesize, NULL,
              UBC_PUSHALL | UBC_INVALIDATE | UBC_SYNC);
#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_lock(data->biglock);
#endif

    err = fdisp_wait_answ(&fdi);
    if (!err) {
        fuse_ticket_release(fdi.tick);

        if (fdvp) {
            fuse_invalidate_attr(fdvp);
        }
        if (tdvp && tdvp != fdvp) {
            fuse_invalidate_attr(tdvp);
        }

        fuse_invalidate_attr(fvp);
        fuse_invalidate_attr(tvp);

        cache_purge(fvp);
        cache_purge(tvp);

        /* Swap sizes */
        off_t tmpfilesize = ffud->filesize;
        ffud->filesize = tfud->filesize;
        tfud->filesize = tmpfilesize;

#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_unlock(data->biglock);
#endif
        ubc_setsize(fvp, (off_t)ffud->filesize);
        ubc_setsize(tvp, (off_t)tfud->filesize);
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_lock(data->biglock);
#endif

        /*
         * We need to increase the iocount of fdvp to make sure it will not be reclaimed
         * when assiginig fvp a new parent.
         */
        vnode_get(fdvp);

        vnode_update_identity(fvp, tdvp, tname, (int)tlen, 0, VNODE_UPDATE_PARENT | VNODE_UPDATE_NAME);
        vnode_update_identity(tvp, fdvp, fname, (int)flen, 0, VNODE_UPDATE_PARENT | VNODE_UPDATE_NAME);

        vnode_put(fdvp);

        /*
         * Another approach (will need additional kernel support to work):
         *
         * vnode_t tmpvp = ffud->vp;
         * ffud->vp = tfud->vp;
         * tfud->vp = tmpvp;
         *
         * vnode_t tmpparentvp = ffud->parentvp;
         * ffud->parentvp = tfud->parentvp;
         * tfud->parentvp = tmpparentvp;
         *
         * off_t tmpfilesize = ffud->filesize;
         * ffud->filesize = tfud->filesize;
         * tfud->filesize = tmpfilesize;
         *
         * struct fuse_vnode_data tmpfud;
         * memcpy(&tmpfud, ffud, sizeof(struct fuse_vnode_data));
         * memcpy(ffud, tfud, sizeof(struct fuse_vnode_data));
         * memcpy(tfud, &tmpfud, sizeof(struct fuse_vnode_data));
         *
         * HNodeExchangeFromFSNode(ffud, tfud);
         */
    }

    return err;
}

#endif /* M_OSXFUSE_ENABLE_EXCHANGE */

/* fsync */

__private_extern__
int
fuse_internal_fsync_fh_callback(struct fuse_ticket *ftick, __unused uio_t uio)
{
    fuse_trace_printf_func();

    if (ftick->tk_aw_ohead.error == ENOSYS) {
        if (fticket_opcode(ftick) == FUSE_FSYNC) {
            fuse_clear_implemented(ftick->tk_data, FSESS_NOIMPLBIT(FSYNC));
        } else if (fticket_opcode(ftick) == FUSE_FSYNCDIR) {
            fuse_clear_implemented(ftick->tk_data, FSESS_NOIMPLBIT(FSYNCDIR));
        } else {
            IOLog("osxfuse: unexpected opcode in sync handling\n");
        }
    }

    return 0;
}

__private_extern__
int
fuse_internal_fsync_fh(vnode_t                 vp,
                       vfs_context_t           context,
                       struct fuse_filehandle *fufh,
                       fuse_op_waitfor_t       waitfor)
{
    int err = 0;
    int op = FUSE_FSYNC;
    struct fuse_abi_data ffsi;
    struct fuse_dispatcher fdi;
    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));

    fuse_trace_printf_func();

    fdisp_init_abi(&fdi, fuse_fsync_in, data);
    if (vnode_isdir(vp)) {
        op = FUSE_FSYNCDIR;
    }

    fdisp_make_vp(&fdi, op, vp, context);
    fuse_abi_data_init(&ffsi, DATOI(data), fdi.indata);

    fuse_fsync_in_set_fh(&ffsi, fufh->fh_id);
    fuse_fsync_in_set_fsync_flags(&ffsi, 1 /* datasync */);

    if (waitfor == FUSE_OP_FOREGROUNDED) {
        err = fdisp_wait_answ(&fdi);
        if (err) {
            if (err == ENOSYS) {
                if (op == FUSE_FSYNC) {
                    fuse_clear_implemented(data, FSESS_NOIMPLBIT(FSYNC));
                } else if (op == FUSE_FSYNCDIR) {
                    fuse_clear_implemented(data, FSESS_NOIMPLBIT(FSYNCDIR));
                }
            }
            goto out;
        }
    } else {
        fuse_insert_callback(fdi.tick, &fuse_internal_fsync_fh_callback);
        fuse_insert_message(fdi.tick);
    }

    fuse_ticket_release(fdi.tick);

out:
    return err;
}

__private_extern__
int
fuse_internal_fsync_vp(vnode_t vp, vfs_context_t context)
{
    struct fuse_filehandle *fufh;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);

    int type, err = 0, tmp_err = 0;

    mount_t mp = vnode_mount(vp);

#if M_OSXFUSE_ENABLE_BIG_LOCK
    struct fuse_data *data = fuse_get_mpdata(mp);
    fuse_biglock_unlock(data->biglock);
#endif
    cluster_push(vp, 0);
#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_lock(data->biglock);
#endif

    /*
     * struct timeval tv;
     * int wait = (waitfor == MNT_WAIT)
     *
     * In another world, we could be doing something like:
     *
     * buf_flushdirtyblks(vp, wait, 0, (char *)"fuse_fsync");
     * microtime(&tv);
     * ...
     */

    /*
     * - UBC and vnode are in lock-step.
     * - Can call vnode_isinuse().
     * - Can call ubc_msync().
     */

    if (!fuse_implemented(fuse_get_mpdata(mp), (vnode_isdir(vp) ?
                FSESS_NOIMPLBIT(FSYNCDIR) : FSESS_NOIMPLBIT(FSYNC)))) {
        err = ENOSYS;
        goto out;
    }

    for (type = 0; type < FUFH_MAXTYPE; type++) {
        fufh = &(fvdat->fufh[type]);
        if (FUFH_IS_VALID(fufh)) {
            tmp_err = fuse_internal_fsync_fh(vp, context, fufh,
                                             FUSE_OP_FOREGROUNDED);
            if (tmp_err) {
                err = tmp_err;
            }
        }
    }

out:
    if ((err == ENOSYS) && !fuse_isnosyncwrites_mp(mp)) {
        err = 0;
    }

    return err;
}

/* getattr sidekicks */
__private_extern__
int
fuse_internal_loadxtimes(vnode_t vp, struct vnode_attr *out_vap,
                         vfs_context_t context)
{
    struct vnode_attr *in_vap = VTOVA(vp);
    struct fuse_data *data = fuse_get_mpdata(vnode_mount(vp));
    struct fuse_dispatcher fdi;
    struct fuse_abi_data fgxo;
    int isvroot = vnode_isvroot(vp);
    struct timespec t = { 0, 0 };
    const struct timespec kZeroTime = { 0, 0 };
    int err = 0;

    if (!(data->dataflags & FSESS_XTIMES)) {
        /* We don't return anything. */
        goto out;
    }

    if (VTOFUD(vp)->c_flag & C_XTIMES_VALID) {
        VATTR_RETURN(out_vap, va_backup_time, in_vap->va_backup_time);
        VATTR_RETURN(out_vap, va_create_time, in_vap->va_create_time);
        goto out;
    }

    if (!fuse_implemented(data, FSESS_NOIMPLBIT(GETXTIMES))) {
        goto fake;
    }

    if (fuse_isdeadfs(vp) && isvroot) {
        goto fake;
    }

    if (!(data->dataflags & FSESS_INITED) && isvroot) {
        goto fake;
    }

    err = fdisp_simple_putget_vp(&fdi, FUSE_GETXTIMES, vp, context);
    if (err) {
        /* We don't ever treat this as a hard error. */
        err = 0;
        goto fake;
    }

    fuse_abi_data_init(&fgxo, DATOI(data), fdi.answ);

    t.tv_sec = (time_t)fuse_getxtimes_out_get_bkuptime(&fgxo); /* XXX: truncation */
    t.tv_nsec = fuse_getxtimes_out_get_bkuptimensec(&fgxo);
    VATTR_RETURN(in_vap, va_backup_time, t);
    VATTR_RETURN(out_vap, va_backup_time, t);

    t.tv_sec = (time_t)fuse_getxtimes_out_get_crtime(&fgxo); /* XXX: truncation */
    t.tv_nsec = fuse_getxtimes_out_get_crtimensec(&fgxo);
    VATTR_RETURN(in_vap, va_create_time, t);
    VATTR_RETURN(out_vap, va_create_time, t);

    fuse_ticket_release(fdi.tick);

    VTOFUD(vp)->c_flag |= C_XTIMES_VALID;

    goto out;

fake:
    VATTR_RETURN(out_vap, va_backup_time, kZeroTime);
    VATTR_RETURN(out_vap, va_create_time, kZeroTime);

out:
    return err;
}

/* setattr sidekicks */
__private_extern__
int
fuse_internal_attr_vat2fsai(mount_t               mp,
                            vnode_t               vp,
                            struct vnode_attr    *vap,
                            struct fuse_abi_data *fsai,
                            uint64_t             *newsize)
{
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

    struct fuse_filehandle *fufh = NULL;
    fufh_type_t fufh_type = FUFH_WRONLY;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);

    int sizechanged = 0;
    uid_t nuid;
    gid_t ngid;
    uint32_t valid = 0;

    if (newsize) {
        *newsize = 0;
    }

    fufh = &(fvdat->fufh[fufh_type]);

    if (!FUFH_IS_VALID(fufh)) {
        fufh_type = FUFH_RDWR;
        fufh = &(fvdat->fufh[fufh_type]);
        if (!FUFH_IS_VALID(fufh)) {
            fufh = NULL;
        }
    }

    if (fufh) {
        fuse_setattr_in_set_fh(fsai, fufh->fh_id);
        valid |= FATTR_FH;
    }

    nuid = VATTR_IS_ACTIVE(vap, va_uid) ? vap->va_uid : (uid_t)VNOVAL;
    if (nuid != (uid_t)VNOVAL) {
        fuse_setattr_in_set_uid(fsai, nuid);
        valid |= FATTR_UID;
    }
    VATTR_SET_SUPPORTED(vap, va_uid);

    ngid = VATTR_IS_ACTIVE(vap, va_gid) ? vap->va_gid : (gid_t)VNOVAL;
    if (ngid != (gid_t)VNOVAL) {
        fuse_setattr_in_set_gid(fsai, ngid);
        valid |= FATTR_GID;
    }
    VATTR_SET_SUPPORTED(vap, va_gid);

    if (VATTR_IS_ACTIVE(vap, va_data_size)) {

        // Truncate to a new value.
        fuse_setattr_in_set_size(fsai, vap->va_data_size);
        sizechanged = 1;
        if (newsize) {
            *newsize = vap->va_data_size;
        }
        valid |= FATTR_SIZE;
    }
    VATTR_SET_SUPPORTED(vap, va_data_size);

    /*
     * Possible timestamps:
     *
     * macOS                                             Linux  FUSE API
     *
     * va_access_time    last access time                atime  atime
     * va_backup_time    last backup time                -      -
     * va_change_time    last metadata change time       ctime* -
     * va_create_time    creation time                   -      -
     * va_modify_time    last data modification time     mtime  mtime
     *
     */

    if (VATTR_IS_ACTIVE(vap, va_access_time)) {
        fuse_setattr_in_set_atime(fsai, vap->va_access_time.tv_sec);
        /* XXX: truncation */
        fuse_setattr_in_set_atimensec(fsai, (uint32_t)vap->va_access_time.tv_nsec);
        valid |=  FATTR_ATIME;
    }
    VATTR_SET_SUPPORTED(vap, va_access_time);

    if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
        fuse_setattr_in_set_mtime(fsai, vap->va_modify_time.tv_sec);
        /* XXX: truncation */
        fuse_setattr_in_set_mtimensec(fsai, (uint32_t)vap->va_modify_time.tv_nsec);
        valid |=  FATTR_MTIME;
    }
    VATTR_SET_SUPPORTED(vap, va_modify_time);

    if (VATTR_IS_ACTIVE(vap, va_backup_time) && fuse_isxtimes_mp(mp)) {
        fuse_setattr_in_set_bkuptime(fsai, vap->va_backup_time.tv_sec);
        /* XXX: truncation */
        fuse_setattr_in_set_bkuptimensec(fsai, (uint32_t)vap->va_backup_time.tv_nsec);
        valid |= FATTR_BKUPTIME;
        VATTR_SET_SUPPORTED(vap, va_backup_time);
    }

    if (VATTR_IS_ACTIVE(vap, va_change_time)) {
        if (fuse_isxtimes_mp(mp)) {
            fuse_setattr_in_set_chgtime(fsai, vap->va_change_time.tv_sec);
            /* XXX: truncation */
            fuse_setattr_in_set_chgtimensec(fsai, (uint32_t)vap->va_change_time.tv_nsec);
            valid |=  FATTR_CHGTIME;
            VATTR_SET_SUPPORTED(vap, va_change_time);
        }
    }

    if (VATTR_IS_ACTIVE(vap, va_create_time) && fuse_isxtimes_mp(mp)) {
        fuse_setattr_in_set_crtime(fsai, vap->va_create_time.tv_sec);
        /* XXX: truncation */
        fuse_setattr_in_set_crtimensec(fsai, (uint32_t)vap->va_create_time.tv_nsec);
        valid |= FATTR_CRTIME;
        VATTR_SET_SUPPORTED(vap, va_create_time);
    }

    if (VATTR_IS_ACTIVE(vap, va_mode)) {
        fuse_setattr_in_set_mode(fsai, (vap->va_mode & ALLPERMS) | (VTTOIF(vnode_vtype(vp)) & S_IFMT));
        valid |= FATTR_MODE;
    }
    VATTR_SET_SUPPORTED(vap, va_mode);

    if (VATTR_IS_ACTIVE(vap, va_flags)) {
        fuse_setattr_in_set_flags(fsai, vap->va_flags);
        valid |= FATTR_FLAGS;
    }
    VATTR_SET_SUPPORTED(vap, va_flags);

    fuse_setattr_in_set_valid(fsai, valid);

    /*
     * We /are/ OK with va_acl, va_guuid, and va_uuuid passing through here.
     */

    return sizechanged;
}

/* readdir */

__private_extern__
int
fuse_internal_readdir(vnode_t                 vp,
                      uio_t                   uio,
                      int                     flags,
                      vfs_context_t           context,
                      struct fuse_filehandle *fufh,
                      struct fuse_iov        *cookediov,
                      int                    *numdirent)
{
    int err = 0;
    struct fuse_dispatcher  fdi;
    struct fuse_abi_data    fri;
    struct fuse_data       *data;
    uint32_t size = 0;

    if (uio_resid(uio) == 0) {
        return 0;
    }

    data = fuse_get_mpdata(vnode_mount(vp));

    fdata_wait_init(data);
    fdisp_init(&fdi, 0);

    /* Note that we DO NOT have a UIO_SYSSPACE here (so no need for p2p I/O). */

    while (uio_resid(uio) > 0) {
        data = fuse_get_mpdata(vnode_mount(vp));

        fdi.iosize = fuse_read_in_sizeof(DATOI(data));
        fdisp_make_vp(&fdi, FUSE_READDIR, vp, context);
        fuse_abi_data_init(&fri, DATOI(data), fdi.indata);

        size = (uint32_t)uio_resid(uio);
        if (flags & VNODE_READDIR_EXTENDED) {
            /*
             * Our user space buffer needs to be smaller since re-packing will
             * expand each struct fuse_dirent.
             *
             * The worse case (when the name length is 8) corresponds to a
             * struct direntry size of 40 bytes (8-byte aligned) and a struct
             * fuse_dirent size of 32 bytes (8-byte aligned). So having a buffer
             * that is 4/5 the size will prevent us from reading more than we
             * can pack.
             */
            size = 4 * size / 5;
        }
        size = (uint32_t)min(size, data->iosize);

        fuse_read_in_set_fh(&fri, fufh->fh_id);
        fuse_read_in_set_offset(&fri, uio_offset(uio));
        fuse_read_in_set_size(&fri, size);
        fuse_read_in_set_read_flags(&fri, 0);
        fuse_read_in_set_lock_owner(&fri, 0);
        fuse_read_in_set_flags(&fri, 0);

        err = fdisp_wait_answ(&fdi);
        if (err) {
            goto out;
        }

        err = fuse_internal_readdir_processdata(vp, uio, flags, size,
                                                fdi.answ, fdi.iosize,
                                                cookediov, numdirent);
        if (err) {
            break;
        }
    }

/* done: */

    if (fdi.tick) {
        fuse_ticket_release(fdi.tick);
    }

out:
    return ((err == -1) ? 0 : err);
}

#define DIRENT32_LEN(namlen) \
    ((sizeof(struct dirent) - (FUSE_MAXNAMLEN + 1) + (namlen) + 1 + 3) & ~3)

#define DIRENT64_LEN(namlen) \
    ((sizeof(struct direntry) - MAXPATHLEN + (namlen) + 1 + 7) & ~7)

__private_extern__
int
fuse_internal_readdir_processdata(vnode_t          vp,
                                  uio_t            uio,
                                  int              flags,
                         __unused size_t           reqsize,
                                  void            *buf,
                                  size_t           bufsize,
                                  struct fuse_iov *cookediov,
                                  int             *numdirent)
{
    int err = 0;
    int cou = 0;
    int n = 0;
    size_t bytesavail = 0;
    size_t freclen = 0;

    struct fuse_dirent *fudge = NULL;
    struct dirent *de32 = NULL;
    struct direntry *de64 = NULL;
    char *de_name = NULL;

    if (bufsize < FUSE_NAME_OFFSET) {
        return -1;
    }

    for (;;) {

        if (bufsize < FUSE_NAME_OFFSET) {
            err = -1;
            break;
        }

        fudge = (struct fuse_dirent *)buf;
        freclen = FUSE_DIRENT_SIZE(fudge);

        cou++;

        if (bufsize < freclen) {
            err = ((cou == 1) ? -1 : 0);
            break;
        }

        /*
         * if (isbzero(buf, FUSE_NAME_OFFSET)) {
         *     // zero-pad incomplete buffer
         *     ...
         *     err = -1;
         *     break;
         * }
         */

        if (!fudge->namelen) {
            err = EINVAL;
            break;
        }

        if (fudge->namelen > FUSE_MAXNAMLEN) {
            err = EIO;
            break;
        }

        if (flags & VNODE_READDIR_EXTENDED) {
            bytesavail = DIRENT64_LEN(fudge->namelen);
        } else {
            bytesavail = DIRENT32_LEN(fudge->namelen);
        }

        if (bytesavail > (size_t)uio_resid(uio)) {
            err = -1;
            break;
        }

        fiov_refresh(cookediov);
        fiov_adjust(cookediov, bytesavail);

        if (flags & VNODE_READDIR_EXTENDED) {
            de64 = (struct direntry *)cookediov->base;
            de64->d_ino = fudge->ino;
            de64->d_seekoff = 0;
            de64->d_reclen = bytesavail;
            de64->d_namlen = fudge->namelen;
            de64->d_type = fudge->type;
            de_name = de64->d_name;
        } else {
            de32 = (struct dirent *)cookediov->base;
            de32->d_ino = (ino_t)fudge->ino;
            de32->d_reclen = bytesavail;
            de32->d_type = fudge->type;
            de32->d_namlen = fudge->namelen;
            de_name = de32->d_name;
        }

        // Filter out any ._* files if the mount is configured as such
        if (fuse_skip_apple_double_mp(vnode_mount(vp),
                                      fudge->name, fudge->namelen)) {
            if (flags & VNODE_READDIR_EXTENDED) {
                de64->d_ino = 0;
                de64->d_type = DT_WHT;
            } else {
                de32->d_ino = 0;
                de32->d_type = DT_WHT;
            }
        }

        memcpy(de_name, (char *)buf + FUSE_NAME_OFFSET, fudge->namelen);
        de_name[fudge->namelen] = '\0';

        err = uiomove(cookediov->base, (int)cookediov->len, uio);
        if (err) {
            break;
        }

        n++;

        buf = (char *)buf + freclen;
        bufsize -= freclen;
        uio_setoffset(uio, fudge->off);
    }

    if (!err && numdirent) {
        *numdirent = n;
    }

    return err;
}

/* remove */

static int
fuse_internal_remove_callback(vnode_t vp, void *cargs)
{
    struct vnode_attr *vap;
    uint64_t target_nlink;

    vap = VTOVA(vp);

    target_nlink = *(uint64_t *)cargs;

    /* somewhat lame "heuristics", but you got better ideas? */
    if ((vap->va_nlink == target_nlink) && vnode_isreg(vp)) {
        fuse_invalidate_attr(vp);
    }

    return VNODE_RETURNED;
}

__private_extern__
int
fuse_internal_remove(vnode_t               dvp,
                     vnode_t               vp,
                     struct componentname *cnp,
                     enum fuse_opcode      op,
                     vfs_context_t         context)
{
    struct fuse_dispatcher fdi;

    struct vnode_attr *vap = VTOVA(vp);
    int need_invalidate = 0;
    uint64_t target_nlink = 0;
    mount_t mp = vnode_mount(vp);
    struct fuse_data *data = fuse_get_mpdata(mp);

    int err = 0;

    fdata_wait_init(data);
    fdisp_init(&fdi, cnp->cn_namelen + 1);
    fdisp_make_vp(&fdi, op, dvp, context);

    memcpy(fdi.indata, cnp->cn_nameptr, cnp->cn_namelen);
    ((char *)fdi.indata)[cnp->cn_namelen] = '\0';

    if ((vap->va_nlink > 1) && vnode_isreg(vp)) {
        need_invalidate = 1;
        target_nlink = vap->va_nlink;
    }

    err = fdisp_wait_answ(&fdi);
    if (!err) {
        fuse_ticket_release(fdi.tick);
    }

    fuse_invalidate_attr(dvp);
    fuse_invalidate_attr(vp);

    /*
     * XXX: M_OSXFUSE_INVALIDATE_CACHED_VATTRS_UPON_UNLINK
     *
     * Consider the case where vap->va_nlink > 1 for the entity being
     * removed. In our world, other in-memory vnodes that share a link
     * count each with this one may not know right way that this one just
     * got deleted. We should let them know, say, through a vnode_iterate()
     * here and a callback that does fuse_invalidate_attr(vp) on each
     * relevant vnode.
     */
    if (need_invalidate && !err) {
        if (!vfs_busy(mp, LK_NOWAIT)) {
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(data->biglock);
#endif
            vnode_iterate(mp, 0, fuse_internal_remove_callback,
                          (void *)&target_nlink);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(data->biglock);
#endif
            vfs_unbusy(mp);
        } else {
            IOLog("osxfuse: skipping link count fixup upon remove\n");
        }
    }

    return err;
}

/* rename */

__private_extern__
int
fuse_internal_rename(vnode_t               fdvp,
            __unused vnode_t               fvp,
                     struct componentname *fcnp,
                     vnode_t               tdvp,
            __unused vnode_t               tvp,
                     struct componentname *tcnp,
                     vfs_context_t         context)
{
    struct fuse_data *data;
    struct fuse_dispatcher fdi;
    struct fuse_abi_data fri;
    void *next;
    int err = 0;

    data = fuse_get_mpdata(vnode_mount(fdvp));

    fdata_wait_init(data);
    fdisp_init(&fdi, fuse_rename_in_sizeof(DATOI(data)) +
                     fcnp->cn_namelen + tcnp->cn_namelen + 2);
    fdisp_make_vp(&fdi, FUSE_RENAME, fdvp, context);
    fuse_abi_data_init(&fri, DATOI(data), fdi.indata);
    next = (char *)fdi.indata + fuse_rename_in_sizeof(DATOI(data));

    fuse_rename_in_set_newdir(&fri, VTOI(tdvp));

    memcpy(next, fcnp->cn_nameptr, fcnp->cn_namelen);
    ((char *)next)[fcnp->cn_namelen] = '\0';

    memcpy((char *)next + fcnp->cn_namelen + 1, tcnp->cn_nameptr,
           tcnp->cn_namelen);
    ((char *)next)[fcnp->cn_namelen + tcnp->cn_namelen + 1] = '\0';

    err = fdisp_wait_answ(&fdi);
    if (!err) {
        fuse_ticket_release(fdi.tick);

        fuse_invalidate_attr(fdvp);
        if (tdvp != fdvp) {
            fuse_invalidate_attr(tdvp);
        }
    }

    return err;
}

/* revoke */

__private_extern__
int
fuse_internal_revoke(vnode_t vp, int flags, vfs_context_t context, int how)
{
    int ret = 0;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);

    fvdat->flag |= FN_REVOKED;

    if (how == REVOKE_HARD) {
        ret = vn_revoke(vp, flags, context);
    }

    return ret;
}

/* strategy */

__private_extern__
int
fuse_internal_strategy(vnode_t vp, buf_t bp)
{
    size_t biosize;
    size_t chunksize;
    size_t respsize;

    bool mapped = false;
    int mode;
    int op;
    int vtype = vnode_vtype(vp);

    int err = 0;

    caddr_t bufdat;
    off_t   left;
    off_t   offset;
    int32_t bflags = buf_flags(bp);

    fufh_type_t             fufh_type;
    struct fuse_dispatcher  fdi;
    struct fuse_data       *data;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);
    struct fuse_filehandle *fufh = NULL;
    mount_t mp = vnode_mount(vp);

    data = fuse_get_mpdata(mp);

    biosize = data->blocksize;

    if (!(vtype == VREG || vtype == VDIR)) {
        err = ENOTSUP;
        goto out;
    }

    if (bflags & B_READ) {
        mode = FREAD;
        fufh_type = FUFH_RDONLY; /* FUFH_RDWR will also do */
    } else {
        mode = FWRITE;
        fufh_type = FUFH_WRONLY; /* FUFH_RDWR will also do */
    }

    if (fvdat->flag & FN_CREATING) {
        fuse_lck_mtx_lock(fvdat->createlock);
        if (fvdat->flag & FN_CREATING) {
#if M_OSXFUSE_ENABLE_BIG_LOCK
            /*
             * We assume, that a call to fuse_vnop_create is always
             * followed by a call to fuse_vnop_open by the same thread.
             *
             * Release biglock and fusenode lock before going to sleep, to
             * allow the creator to enter fuse_vnop_open, clear the flag
             * FN_CREATING and wake us up.
             *
             * See fuse_vnop_open for more details.
             */
            fuse_biglock_unlock(data->biglock);
            fuse_nodelock_unlock(VTOFUD(vp));
#endif
            (void)fuse_msleep(fvdat->creator, fvdat->createlock,
                              PDROP | PINOD | PCATCH, "fuse_internal_strategy",
                              NULL, data);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_nodelock_lock(VTOFUD(vp), FUSEFS_EXCLUSIVE_LOCK);
            fuse_biglock_lock(data->biglock);
#endif
        } else {
            fuse_lck_mtx_unlock(fvdat->createlock);
        }
    }

    fufh = &(fvdat->fufh[fufh_type]);

    if (!FUFH_IS_VALID(fufh)) {
        fufh_type = FUFH_RDWR;
        fufh = &(fvdat->fufh[fufh_type]);
        if (!FUFH_IS_VALID(fufh)) {
            fufh = NULL;
        } else {
            /* We've successfully fallen back to FUFH_RDWR. */
        }
    }

    if (!fufh) {

        if (mode == FREAD) {
            fufh_type = FUFH_RDONLY;
        } else {
            fufh_type = FUFH_RDWR;
        }

        /*
         * Lets NOT do the filehandle preflight check here.
         */

        err = fuse_filehandle_get(vp, NULL, fufh_type, 0 /* mode */);

        if (!err) {
            fufh = &(fvdat->fufh[fufh_type]);
            FUFH_AUX_INC(fufh);
            /* We've created a NEW fufh of type fufh_type. open_count is 1. */
        }

    } else { /* good fufh */

        FUSE_OSAddAtomic(1, (SInt32 *)&fuse_fh_reuse_count);

        /* We're using an existing fufh of type fufh_type. */
    }

    if (err) {
        /* A more typical error case. */
        if ((err == ENOTCONN) || fuse_isdeadfs(vp)) {
            err = EIO;
            goto out;
        }

        IOLog("osxfuse: strategy failed to get fh "
              "(vtype=%d, fufh_type=%d, err=%d)\n", vtype, fufh_type, err);

        if (!vfs_issynchronous(mp)) {
            IOLog("osxfuse: asynchronous write failed!\n");
        }

        err = EIO;
        goto out;
    }

    if (!fufh) {
        panic("osxfuse: tried everything but still no fufh");
        /* NOTREACHED */
    }

#define B_INVAL 0x00040000 /* Does not contain valid info. */
#define B_ERROR 0x00080000 /* I/O error occurred. */

    if (bflags & B_INVAL) {
        IOLog("osxfuse: buffer does not contain valid information\n");
    }

    if (bflags & B_ERROR) {
        IOLog("osxfuse: an I/O error has occured\n");
    }

    if (buf_count(bp) == 0) {
        goto out;
    }

    fdata_wait_init(data);
    fdisp_init(&fdi, 0);

    if (mode == FREAD) {

        struct fuse_abi_data fri;

        buf_setresid(bp, buf_count(bp));
        offset = (off_t)((off_t)buf_blkno(bp) * biosize);

        if (offset >= fvdat->filesize) {
            /* Trying to read at/after EOF? */
            if (offset != fvdat->filesize) {
                /* Trying to read after EOF? */
                err = EINVAL;
            }
            goto out;
        }

        /* Note that we just made sure that offset < fvdat->filesize. */
        if ((offset + buf_count(bp)) > fvdat->filesize) {
            /* Trimming read */
            buf_setcount(bp, (uint32_t)(fvdat->filesize - offset));
        }

#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_unlock(data->biglock);
#endif
        err = buf_map(bp, &bufdat);
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_lock(data->biglock);
#endif
        if (err) {
            IOLog("osxfuse: failed to map buffer in strategy\n");
            err = EFAULT;
            goto out;
        } else {
            mapped = true;
        }

        while (buf_resid(bp) > 0) {

            chunksize = min((size_t)buf_resid(bp), VTOVA(vp)->va_iosize);

            fdi.iosize = fuse_read_in_sizeof(DATOI(data));

            op = FUSE_READ;
            if (vtype == VDIR) {
                op = FUSE_READDIR;
            }
            fdisp_make_vp(&fdi, op, vp, NULL);
            fuse_abi_data_init(&fri, DATOI(data), fdi.indata);

            fuse_read_in_set_fh(&fri, fufh->fh_id);

            /*
             * Historical note:
             *
             * fri->offset = ((off_t)(buf_blkno(bp))) * biosize;
             *
             * This wasn't being incremented!?
             */

            fuse_read_in_set_offset(&fri, offset);
            fuse_read_in_set_size(&fri, (uint32_t)chunksize);
            fuse_read_in_set_read_flags(&fri, 0);
            fuse_read_in_set_lock_owner(&fri, 0);
            fuse_read_in_set_flags(&fri, 0);

            fdi.tick->tk_aw_type = FT_A_BUF;
            fdi.tick->tk_aw_bufdata = bufdat;

            err = fdisp_wait_answ(&fdi);
            if (err) {
                /* There was a problem with reading. */
                goto out;
            }

            respsize = fdi.tick->tk_aw_bufsize;

            buf_setresid(bp, (uint32_t)(buf_resid(bp) - respsize));
            bufdat += respsize;
            offset += respsize;

            /* Did we hit EOF before being done? */
            if ((respsize == 0) && (buf_resid(bp) > 0)) {
                 /*
                  * Historical note:
                  * If we don't get enough data, just fill the rest with zeros.
                  * In NFS context, this would mean a hole in the file.
                  */

                 /* Zero-pad the incomplete buffer. */
                 bzero(bufdat, buf_resid(bp));
                 buf_setresid(bp, 0);
                 break;
            }
        } /* while (buf_resid(bp) > 0) */
    } else {
        /* write */
        struct fuse_abi_data fwi;
        struct fuse_abi_data fwo;
        uint32_t size;
        off_t diff;

#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_unlock(data->biglock);
#endif
        err = buf_map(bp, &bufdat);
#if M_OSXFUSE_ENABLE_BIG_LOCK
        fuse_biglock_lock(data->biglock);
#endif
        if (err) {
            IOLog("osxfuse: failed to map buffer in strategy\n");
            err = EFAULT;
            goto out;
        } else {
            mapped = true;
        }

        /* Write begin */

        buf_setresid(bp, buf_count(bp));
        offset = (off_t)((off_t)buf_blkno(bp) * biosize);

        /* XXX: TBD -- Check here for extension (writing past end) */

        left = buf_count(bp);

        while (left > 0) {

            chunksize = min((size_t)left, VTOVA(vp)->va_iosize);

            fdi.iosize = fuse_write_in_sizeof(DATOI(data));
            op = FUSE_WRITE;

            fdisp_make_vp(&fdi, op, vp, NULL);

            /* Take the size of the write buffer into account */
            fdi.finh->len += (typeof(fdi.finh->len))chunksize;

            fuse_abi_data_init(&fwi, DATOI(data), fdi.indata);

            fuse_write_in_set_fh(&fwi, fufh->fh_id);
            fuse_write_in_set_offset(&fwi, offset);
            fuse_write_in_set_size(&fwi, (uint32_t)chunksize);
            fuse_write_in_set_write_flags(&fwi, 0);
            fuse_write_in_set_lock_owner(&fwi, 0);
            fuse_write_in_set_flags(&fwi, FUSE_WRITE_CACHE);

            fdi.tick->tk_ms_type = FT_M_BUF;
            fdi.tick->tk_ms_bufdata = bufdat;
            fdi.tick->tk_ms_bufsize = chunksize;

            /* About to write <chunksize> at <offset> */

            err = fdisp_wait_answ(&fdi);
            if (err) {
                break;
            }

            fuse_abi_data_init(&fwo, DATOI(data), fdi.answ);
            size = fuse_write_out_get_size(&fwo);

            diff = chunksize - size;

            if (diff < 0) {
                err = EINVAL;
                break;
            }

            left -= size;
            bufdat += size;
            offset += size;
            buf_setresid(bp, (uint32_t)left);

            if (diff > 0) {
                /*
                 * The write operation could not be fully executed. In case of
                 * synchronous I/O the kernel will report an EIO error back to
                 * the process that issued the I/O.
                 */
                break;
            }
        }
    }

    if (fdi.tick) {
        fuse_ticket_release(fdi.tick);
    }

out:

    if (err) {
        buf_seterror(bp, err);
    }

    if (mapped) {
        buf_unmap(bp);
    }

    buf_biodone(bp);

    return err;
}

__private_extern__
errno_t
fuse_internal_strategy_buf(struct vnop_strategy_args *ap)
{
    int32_t   bflags;
    upl_t     bupl;
    daddr64_t blkno, lblkno;
    buf_t     bp    = ap->a_bp;
    vnode_t   vp    = buf_vnode(bp);
    int       vtype = vnode_vtype(vp);

    struct fuse_data *data;

    if (!vp || vtype == VCHR || vtype == VBLK) {
        panic("osxfuse: buf_strategy: b_vp == NULL || vtype == VCHR | VBLK\n");
    }

    bflags = buf_flags(bp);

    bupl = buf_upl(bp);
    blkno = buf_blkno(bp);
    lblkno = buf_lblkno(bp);

    if (!(bflags & B_CLUSTER)) {

        data = fuse_get_mpdata(vnode_mount(vp));

        if (bupl) {
            int retval;

#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_unlock(data->biglock);
#endif
            retval = cluster_bp(bp);
#if M_OSXFUSE_ENABLE_BIG_LOCK
            fuse_biglock_lock(data->biglock);
#endif
            return retval;
        }

        if (blkno == lblkno) {
            off_t  f_offset;
            size_t contig_bytes;

            // Still think this is a kludge?
            f_offset = lblkno * data->blocksize;
            blkno = f_offset / data->blocksize;

            buf_setblkno(bp, blkno);

            contig_bytes = buf_count(bp);

            if (blkno == -1) {
                buf_clear(bp);
            }

            /*
             * Our "device" is always /all contiguous/. We don't wanna be
             * doing things like:
             *
             * ...
             *     else if ((long)contig_bytes < buf_count(bp)) {
             *         ret = buf_strategy_fragmented(devvp, bp, f_offset,
             *                                       contig_bytes));
             *         return ret;
             *      }
             */
        }

        if (blkno == -1) {
            buf_biodone(bp);
            return 0;
        }
    }

    // Issue the I/O

    return fuse_internal_strategy(vp, bp);
}

/* entity creation */

__private_extern__
void
fuse_internal_newentry_makerequest(mount_t                 mp,
                                   uint64_t                dnid,
                                   struct componentname   *cnp,
                                   enum fuse_opcode        op,
                                   void                   *buf,
                                   size_t                  bufsize,
                                   struct fuse_dispatcher *fdip,
                                   vfs_context_t           context)
{
    fdip->iosize = bufsize + cnp->cn_namelen + 1;

    fdisp_make(fdip, op, mp, dnid, context);
    memcpy(fdip->indata, buf, bufsize);
    memcpy((char *)fdip->indata + bufsize, cnp->cn_nameptr, cnp->cn_namelen);
    ((char *)fdip->indata)[bufsize + cnp->cn_namelen] = '\0';
}

__private_extern__
int
fuse_internal_newentry_core(vnode_t                 dvp,
                            vnode_t                *vpp,
                            struct componentname   *cnp,
                            enum vtype              vtyp,
                            struct fuse_dispatcher *fdip,
                            vfs_context_t           context)
{
    int err = 0;
    struct fuse_abi_data feo;
    mount_t mp = vnode_mount(dvp);
    struct fuse_data *data = fuse_get_mpdata(mp);

    err = fdisp_wait_answ(fdip);
    if (err) {
        return err;
    }

    fuse_abi_data_init(&feo, DATOI(data), fdip->answ);

    err = fuse_internal_checkentry(&feo, vtyp);
    if (err) {
        goto out;
    }

    err = fuse_vget_i(vpp, 0 /* flags */, &feo, cnp, dvp, mp, context);
    if (err) {
        uint64_t nodeid = fuse_entry_out_get_nodeid(&feo);
        fuse_internal_forget_send(mp, context, nodeid, 1, fdip);
        goto out;
    }

    cache_attrs(*vpp, fuse_entry_out, &feo);

out:
    fuse_ticket_release(fdip->tick);

    return err;
}

__private_extern__
int
fuse_internal_newentry(vnode_t               dvp,
                       vnode_t              *vpp,
                       struct componentname *cnp,
                       enum fuse_opcode      op,
                       void                 *buf,
                       size_t                bufsize,
                       enum vtype            vtype,
                       vfs_context_t         context)
{
    int err;
    struct fuse_dispatcher fdi;
    mount_t mp = vnode_mount(dvp);

    if (fuse_skip_apple_double_mp(mp, cnp->cn_nameptr, cnp->cn_namelen)) {
        return EACCES;
    }

    fdisp_init(&fdi, 0);
    fuse_internal_newentry_makerequest(mp, VTOI(dvp), cnp, op, buf, bufsize,
                                       &fdi, context);
    /* Note: fuse_internal_newentry_core releases fdi.tick */
    err = fuse_internal_newentry_core(dvp, vpp, cnp, vtype, &fdi, context);
    fuse_invalidate_attr(dvp);

    return err;
}

/* entity destruction */

__private_extern__
int
fuse_internal_forget_callback(struct fuse_ticket *ftick, __unused uio_t uio)
{
    struct fuse_dispatcher fdi;

    fdi.tick = ftick;

    fuse_internal_forget_send(ftick->tk_data->mp, NULL,
        ((struct fuse_in_header *)ftick->tk_ms_fiov.base)->nodeid, 1, &fdi);

    return 0;
}

__private_extern__
void
fuse_internal_forget_send(mount_t                 mp,
                          vfs_context_t           context,
                          uint64_t                nodeid,
                          uint64_t                nlookup,
                          struct fuse_dispatcher *fdip)
{
    struct fuse_data *data;
    struct fuse_abi_data ffi;

    /*
     * KASSERT(nlookup > 0, ("zero-times forget for vp #%llu",
     *         (long long unsigned) nodeid));
     */

    data = fuse_get_mpdata(mp);

    fdip->iosize = fuse_forget_in_sizeof(DATOI(data));
    fdisp_make(fdip, FUSE_FORGET, mp, nodeid, context);
    fuse_abi_data_init(&ffi, DATOI(data), fdip->indata);

    fuse_forget_in_set_nlookup(&ffi, nlookup);

    fuse_insert_message(fdip->tick);
}

static int
fuse_internal_interrupt_handler(struct fuse_ticket *ftick, __unused uio_t uio)
{
    fuse_lck_mtx_lock(ftick->tk_mtx);

    if (fticket_answered(ftick)) {
        goto out;
    }

    if (ftick->tk_aw_ohead.error == EAGAIN) {
        bzero(&ftick->tk_aw_ohead, sizeof(struct fuse_out_header));
        ftick->tk_flag &= ~FT_DIRTY;

        fuse_insert_callback(ftick, &fuse_internal_interrupt_handler);
        fuse_insert_message_head(ftick);
    }

out:
    fuse_lck_mtx_unlock(ftick->tk_mtx);

    return 0;
}

__private_extern__
void
fuse_internal_interrupt_send(struct fuse_ticket *ftick)
{
    struct fuse_data *data;
    struct fuse_dispatcher fdi;
    struct fuse_abi_data fii;

    data = ftick->tk_data;

    fdisp_init_abi(&fdi, fuse_interrupt_in, data);
    fdisp_make(&fdi, FUSE_INTERRUPT, data->mp, (uint64_t)0, NULL);
    fuse_abi_data_init(&fii, DATOI(data), fdi.indata);

    fuse_interrupt_in_set_unique(&fii, ftick->tk_unique);

    /*
     * To prevent the following race condition do not reuse the ticket of the
     * interrupt request.
     *
     * - We send an interrupt request to the FUSE server.
     * - The FUSE server responds to the interrupted request before processing
     *   our interupt request.
     * - We drop the interrupt request ticket and reuse it for a new request.
     * - The server answers our interrupt request.
     */
    fticket_set_kill(fdi.tick);

    ftick->tk_interrupt = fdi.tick;

    fuse_insert_callback(fdi.tick, &fuse_internal_interrupt_handler);
    fuse_insert_message_head(fdi.tick);

    /*
     * Note: The interrupt ticket is released in fuse_standard_handler when
     * processing the answer to the original ticket.
     */
}

__private_extern__
void
fuse_internal_interrupt_remove(struct fuse_ticket *interrupt)
{
    /*
     * Set interrupt ticket state to answered and remove the callback. Pending
     * requests, that are already marked as answered, will not be sent to user
     * space.
     *
     * Note: Simply removing the ticket from the message queue would break
     * fuse_device_select.
     */

    fuse_lck_mtx_lock(interrupt->tk_mtx);
    fticket_set_answered(interrupt);
    fuse_lck_mtx_unlock(interrupt->tk_mtx);

    fuse_remove_callback(interrupt);
}

__private_extern__
void
fuse_internal_vnode_disappear(vnode_t vp, vfs_context_t context, int how)
{
    int err = 0;

    fuse_vncache_purge(vp);

    if (how != REVOKE_NONE) {
        err = fuse_internal_revoke(vp, REVOKEALL, context, how);
        if (err) {
            IOLog("osxfuse: disappearing act: revoke failed (%d)\n", err);
        }

        /*
         * Checking whether the vnode is in the process of being recycled to avoid the
         * 'vnode reclaim in progress' kernel panic.
         *
         * Obviously this is a quick fix done without much understanding of the code
         * flow of a recycle operation, but it seems that we shouldn't call this again
         * if a recycle operation was the reason that we got here.
         */
        if (!vnode_isrecycled(vp)) {
            err = vnode_recycle(vp);
            if (err) {
                IOLog("osxfuse: disappearing act: recycle failed (%d)\n", err);
            }
        } else {
            IOLog("osxfuse: Avoided 'vnode reclaim in progress' kernel panic. What now?\n");
        }
    }
}

/* fuse start/stop */

#if M_OSXFUSE_ENABLE_UNSUPPORTED

static
void
fuse_internal_update_vfsstat(void *parameter, __unused wait_result_t wait_result)
{
    int err = 0;

    vnode_t rootvp = (vnode_t)parameter;
    uint32_t vid = vnode_vid(rootvp);

    vnode_rele(rootvp);

    err = vnode_getwithvid(rootvp, vid);
    if (err) {
        goto out;
    }

    vfs_context_t context = vfs_context_create(NULL);

    err = vfs_update_vfsstat(vnode_mount(rootvp), context, VFS_KERNEL_EVENT);
    if (err) {
        IOLog("osxfuse: failed to update vfsstat (err=%d)\n", err);
    }

    vfs_context_rele(context);

    (void)vnode_put(rootvp);

out:
    thread_terminate(current_thread());
}

#endif /* M_OSXFUSE_ENABLE_UNSUPPORTED */

static
int
fuse_internal_init_handler(struct fuse_ticket *ftick, __unused uio_t uio)
{
    int err = 0;

    struct fuse_data *data = ftick->tk_data;
    struct fuse_init_out *fio_raw;
    struct fuse_abi_data fio;

    vnode_t rootvp;

    fuse_lck_mtx_lock(ftick->tk_mtx);

    if (fticket_answered(ftick)) {
        fuse_lck_mtx_unlock(ftick->tk_mtx);
        goto out;
    }

    fticket_set_answered(ftick);

    err = fticket_pull(ftick, uio);
    ftick->tk_aw_errno = err;
    if (err) {
        fuse_lck_mtx_unlock(ftick->tk_mtx);
        goto out;
    }

    fuse_lck_mtx_unlock(ftick->tk_mtx);

#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_lock(data->biglock);
#endif

    err = ftick->tk_aw_ohead.error;
    if (err) {
        IOLog("osxfuse: user space initialization failed (%d)\n", err);
        goto out_biglock;
    }

    fio_raw = (struct fuse_init_out *)fticket_resp(ftick)->base;
    DTOABI(data)->major = fio_raw->major;
    DTOABI(data)->minor = fio_raw->minor;

    if (ABITOI(DTOABI(data)) < FUSE_ABI_VERSION_MIN) {
        IOLog("osxfuse: ABI version of user space library too low\n");
        err = EPROTONOSUPPORT;
        goto out_biglock;
    }

    fuse_abi_data_init(&fio, DATOI(data), fticket_resp(ftick)->base);

    data->max_write = fuse_init_out_get_max_write(&fio);

    uint32_t flags = fuse_init_out_get_flags(&fio);

    if (ABITOI(DTOABI(data)) >= 719) {
        if (!(flags & FUSE_ALLOCATE)) {
            fuse_clear_implemented(data, FSESS_NOIMPLBIT(FALLOCATE));
        }
        if (!(flags & FUSE_EXCHANGE_DATA)) {
            fuse_clear_implemented(data, FSESS_NOIMPLBIT(EXCHANGE));
        }
    }

    if (flags & FUSE_CASE_INSENSITIVE) {
        data->dataflags |= FSESS_CASE_INSENSITIVE;
    }
    if (!(flags & FUSE_VOL_RENAME)) {
        fuse_clear_implemented(data, FSESS_NOIMPLBIT(SETVOLNAME));
    }
    if (flags & FUSE_XTIMES) {
        data->dataflags |= FSESS_XTIMES;
    } else {
        fuse_clear_implemented(data, FSESS_NOIMPLBIT(GETXTIMES));
    }
    if (flags & FUSE_ATOMIC_O_TRUNC) {
        data->dataflags |= FSESS_ATOMIC_O_TRUNC;
    }

    /*
     * Ignore the congestion_threshold field of struct fuse_init_out because
     * there is no equivalent to the Linux backing device info concept (struct
     * backing_dev_info) on macOS.
     */

    fuse_lck_mtx_lock(data->ticket_mtx);
    data->dataflags |= FSESS_INITED;
    fuse_wakeup(&data->ticketer);
    fuse_lck_mtx_unlock(data->ticket_mtx);

#if M_OSXFUSE_ENABLE_UNSUPPORTED
    rootvp = data->rootvp;
    if (rootvp != NULLVP) {
        kern_return_t kr;
        thread_t vfsstat_thread;

        err = vnode_ref(rootvp);
        if (err) {
            goto out_biglock;
        }

        kr = kernel_thread_start(fuse_internal_update_vfsstat, rootvp, &vfsstat_thread);
        if (kr == KERN_SUCCESS) {
            thread_deallocate(vfsstat_thread);
        } else {
            IOLog("osxfuse: could not start vfsstat update thread\n");
            vnode_rele(rootvp);
        }
    }
#endif /* M_OSXFUSE_ENABLE_UNSUPPORTED */

out_biglock:
#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_unlock(data->biglock);
#endif

out:
    if (err) {
        fdata_set_dead(data, false);
    }

    return ftick->tk_aw_errno;
}

__private_extern__
void
fuse_internal_init(struct fuse_data *data, vfs_context_t context)
{
    struct fuse_init_in *fiii;
    struct fuse_dispatcher fdi;

    fdisp_init(&fdi, sizeof(*fiii));
    fdisp_make(&fdi, FUSE_INIT, data->mp, 0, context);
    fiii = fdi.indata;
    fiii->major = FUSE_KERNEL_VERSION;
    fiii->minor = FUSE_KERNEL_MINOR_VERSION;
    fiii->max_readahead = data->iosize * 16;
    fiii->flags = FUSE_ATOMIC_O_TRUNC | FUSE_ALLOCATE | FUSE_EXCHANGE_DATA | FUSE_CASE_INSENSITIVE | FUSE_VOL_RENAME | FUSE_XTIMES;

    fuse_insert_callback(fdi.tick, &fuse_internal_init_handler);
    fuse_insert_message(fdi.tick);

    fuse_ticket_release(fdi.tick);
}

/* other */

static int
fuse_internal_print_vnodes_callback(vnode_t vp, __unused void *cargs)
{
    const char *vname = NULL;
    struct fuse_vnode_data *fvdat = VTOFUD(vp);

#if M_OSXFUSE_ENABLE_UNSUPPORTED
    vname = vnode_getname(vp);
#endif /* M_OSXFUSE_ENABLE_UNSUPPORTED */

    if (vname) {
        IOLog("osxfuse: vp=%p ino=%lld parent=%lld inuse=%d %s\n",
              vp, fvdat->nodeid, fvdat->parent_nodeid,
              vnode_isinuse(vp, 0), vname);
    } else {
        if (fvdat->nodeid == FUSE_ROOT_ID) {
            IOLog("osxfuse: vp=%p ino=%lld parent=%lld inuse=%d /\n",
                  vp, fvdat->nodeid, fvdat->parent_nodeid,
                  vnode_isinuse(vp, 0));
        } else {
            IOLog("osxfuse: vp=%p ino=%lld parent=%lld inuse=%d\n",
                  vp, fvdat->nodeid, fvdat->parent_nodeid,
                  vnode_isinuse(vp, 0));
        }
    }

#if M_OSXFUSE_ENABLE_UNSUPPORTED
    if (vname) {
        vnode_putname(vname);
    }
#endif /* M_OSXFUSE_ENABLE_UNSUPPORTED */

    return VNODE_RETURNED;
}

__private_extern__
void
fuse_internal_print_vnodes(mount_t mp)
{
    vnode_iterate(mp, VNODE_ITERATE_ALL,
                  fuse_internal_print_vnodes_callback, NULL);
}

__private_extern__
void
fuse_preflight_log(vnode_t vp, fufh_type_t fufh_type, int err, char *message)
{
    const char *vname = NULL;

#if M_OSXFUSE_ENABLE_UNSUPPORTED
    vname = vnode_getname(vp);
#else
    (void)vname;
    (void)vp;
#endif /* M_OSXFUSE_ENABLE_UNSUPPORTED */

    if (vname) {
        IOLog("osxfuse: file handle preflight "
              "(caller=%s, type=%d, err=%d, name=%s)\n",
              message, fufh_type, err, vname);
    } else {
        IOLog("osxfuse: file handle preflight "
              "(caller=%s, type=%d, err=%d)\n", message, fufh_type, err);
    }

#if M_OSXFUSE_ENABLE_UNSUPPORTED
    if (vname) {
        vnode_putname(vname);
    }
#endif /* M_OSXFUSE_ENABLE_UNSUPPORTED */
}
