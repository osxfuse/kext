/*
 * Copyright (C) 2006-2007 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#include "fuse.h"
#include "fuse_device.h"
#include "fuse_ipc.h"
#include "fuse_internal.h"
#include "fuse_locking.h"
#include "fuse_nodehash.h"
#include "fuse_sysctl.h"

#include <fuse_ioctl.h>
#include <libkern/libkern.h>

#define FUSE_DEVICE_GLOBAL_LOCK()   fuse_lck_mtx_lock(fuse_device_mutex)
#define FUSE_DEVICE_GLOBAL_UNLOCK() fuse_lck_mtx_unlock(fuse_device_mutex)
#define FUSE_DEVICE_LOCAL_LOCK(d)   fuse_lck_mtx_lock((d)->mtx)
#define FUSE_DEVICE_LOCAL_UNLOCK(d) fuse_lck_mtx_unlock((d)->mtx)

#define TAILQ_FOREACH_SAFE(var, head, field, tvar)           \
        for ((var) = TAILQ_FIRST((head));                    \
            (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
            (var) = (tvar))

static int    fuse_cdev_major          = -1;
static UInt32 fuse_interface_available = FALSE;

struct fuse_device {
    lck_mtx_t        *mtx;
    int               usecount;
    pid_t             pid;
    uint32_t          random;
    dev_t             dev;
    void             *cdev;
    struct fuse_data *data;
};

static struct fuse_device fuse_device_table[FUSE_NDEVICES];

#define FUSE_DEVICE_FROM_UNIT_FAST(u) (fuse_device_t)&(fuse_device_table[(u)])

/* Interface for VFS */

/* Doesn't need lock. */
fuse_device_t
fuse_device_get(dev_t dev)
{
    int unit = minor(dev);

    if ((unit < 0) || (unit >= FUSE_NDEVICES)) {
        return (fuse_device_t)0;
    }

    return FUSE_DEVICE_FROM_UNIT_FAST(unit);
}

__inline__
void
fuse_device_lock(fuse_device_t fdev)
{
    FUSE_DEVICE_LOCAL_LOCK(fdev);
}

__inline__
void
fuse_device_unlock(fuse_device_t fdev)
{
    FUSE_DEVICE_LOCAL_UNLOCK(fdev);
}

/* Must be called under lock. */
__inline__
struct fuse_data *
fuse_device_get_mpdata(fuse_device_t fdev)
{
    return fdev->data;
}

/* Must be called under lock. */
__inline__
uint32_t
fuse_device_get_random(fuse_device_t fdev)
{
    return fdev->random;
}

/* Must be called under lock. */
__inline__
void
fuse_device_close_final(fuse_device_t fdev)
{
    if (fdev) {
        fdata_destroy(fdev->data);
        fdev->data   = NULL;
        fdev->pid    = -1;
        fdev->random = 0;
    }
}

/* /dev/fuseN implementation */

d_open_t  fuse_device_open;
d_close_t fuse_device_close;
d_read_t  fuse_device_read;
d_write_t fuse_device_write;
d_ioctl_t fuse_device_ioctl;

static struct cdevsw fuse_device_cdevsw = {
    /* open     */ fuse_device_open,
    /* close    */ fuse_device_close,
    /* read     */ fuse_device_read,
    /* write    */ fuse_device_write,
    /* ioctl    */ fuse_device_ioctl,
    /* stop     */ (d_stop_t *)enodev,
    /* reset    */ (d_reset_t *)enodev,
    /* ttys     */ 0,
    /* select   */ (d_select_t *)enodev,
    /* mmap     */ (d_mmap_t *)enodev,
    /* strategy */ (d_strategy_t *)enodev_strat,
    /* getc     */ (d_getc_t *)enodev,
    /* putc     */ (d_putc_t *)enodev,
    /* flags    */ D_TTY,
};

int
fuse_device_open(dev_t dev, __unused int flags, __unused int devtype,
                 struct proc *p)
{
    int unit;
    struct fuse_device *fdev;
    struct fuse_data  *fdata;

    fuse_trace_printf_func();

    if (fuse_interface_available == FALSE) {
        return ENOENT;
    }

    unit = minor(dev);
    if ((unit >= FUSE_NDEVICES) || (unit < 0)) {
        FUSE_DEVICE_GLOBAL_UNLOCK();
        return ENOENT;
    }

    fdev = FUSE_DEVICE_FROM_UNIT_FAST(unit);
    if (!fdev) {
        FUSE_DEVICE_GLOBAL_UNLOCK();
        IOLog("MacFUSE: device found with no softc\n");
        return ENXIO;
    }

    FUSE_DEVICE_GLOBAL_LOCK();

    if (fdev->usecount != 0) {
        FUSE_DEVICE_GLOBAL_UNLOCK();
        return EBUSY;
    }

    fdev->usecount++;

    FUSE_DEVICE_LOCAL_LOCK(fdev);

    FUSE_DEVICE_GLOBAL_UNLOCK();

    /* Could block. */
    fdata = fdata_alloc(p);

    if (fdev->data) {
        /*
         * This slot isn't currently open by a user daemon. However, it was
         * used earlier for a mount that's still lingering, even though the
         * user daemon is dead.
         */

        FUSE_DEVICE_GLOBAL_LOCK();

        fdev->usecount--;

        FUSE_DEVICE_LOCAL_UNLOCK(fdev);

        FUSE_DEVICE_GLOBAL_UNLOCK();

        fdata_destroy(fdata);

        return EBUSY;
    } else {
        fdata->dataflags |= FSESS_OPENED;
        fdata->fdev  = fdev;
        fdev->data   = fdata;
        fdev->pid    = proc_pid(p);
        fdev->random = random();
    }       

    FUSE_DEVICE_LOCAL_UNLOCK(fdev);

    return KERN_SUCCESS;
}

int
fuse_device_close(dev_t dev, __unused int flags, __unused int devtype,
                  __unused struct proc *p)
{
    int unit;
    struct fuse_device *fdev;
    struct fuse_data  *data;

    fuse_trace_printf_func();

    unit = minor(dev);
    if (unit >= FUSE_NDEVICES) {
        return ENOENT;
    }

    fdev = FUSE_DEVICE_FROM_UNIT_FAST(unit);
    if (!fdev) {
        return ENXIO;
    }

    data = fdev->data;
    if (!data) {
        panic("MacFUSE: no device private data in device_close");
    }

    fdata_dead_set(data);

    FUSE_DEVICE_LOCAL_LOCK(fdev);

    data->dataflags &= ~FSESS_OPENED;

    fuse_lck_mtx_lock(data->aw_mtx);

    if (data->mount_state == FM_MOUNTED) {

        /* Uh-oh, the device is closing but we're still mounted. */

        struct fuse_ticket *ftick;

        while ((ftick = fuse_aw_pop(data))) {
            fuse_lck_mtx_lock(ftick->tk_aw_mtx);
            fticket_set_answered(ftick);
            ftick->tk_aw_errno = ENOTCONN;
            fuse_wakeup(ftick);
            fuse_lck_mtx_unlock(ftick->tk_aw_mtx);
        }

        fuse_lck_mtx_unlock(data->aw_mtx);

        /* Left mpdata for unmount to destroy. */

    } else {

        /* We're not mounted. Can destroy mpdata. */

        fdev->data   = NULL;
        fdev->pid    = -1;
        fdev->random = 0;
        fdata_destroy(data);
    }

    FUSE_DEVICE_LOCAL_UNLOCK(fdev);

    FUSE_DEVICE_GLOBAL_LOCK();

    /*
     * Even if usecount goes 0 here, at open time, we check if fdev->data
     * is non-NULL (that is, a lingering mount). If so, we return EBUSY.
     * We could make the usecount depend on both device-use and mount-state,
     * but I think this is truer to reality, if a bit more complex to maintain.
     */
    fdev->usecount--;

    FUSE_DEVICE_GLOBAL_UNLOCK();

    return KERN_SUCCESS;
}

int
fuse_device_read(dev_t dev, uio_t uio, __unused int ioflag)
{
    int i, err = 0;
    int buflen[3];
    void *buf[] = { NULL, NULL, NULL };

    struct fuse_device  *fdev;
    struct fuse_data   *data;
    struct fuse_ticket *ftick;

    fuse_trace_printf_func();

    fdev = FUSE_DEVICE_FROM_UNIT_FAST(minor(dev));
    if (!fdev) {
        return ENXIO;
    }

    data = fdev->data;

    fuse_lck_mtx_lock(data->ms_mtx);

    /* The read loop (outgoing messages to the user daemon). */

again:
    if (fdata_dead_get(data)) {
        fuse_lck_mtx_unlock(data->ms_mtx);
        return ENODEV;
    }

    if (!(ftick = fuse_ms_pop(data))) {
        err = fuse_msleep(data, data->ms_mtx, PCATCH, "fu_msg", NULL);
        if (err != 0) {
            fuse_lck_mtx_unlock(data->ms_mtx);
            return (fdata_dead_get(data) ? ENODEV : err);
        }
        ftick = fuse_ms_pop(data);
    }

    if (!ftick) {
        goto again;
    }

    fuse_lck_mtx_unlock(data->ms_mtx);

    if (fdata_dead_get(data)) {
         if (ftick) {
             fuse_ticket_drop_invalid(ftick);
         }
         return ENODEV;
    }

    switch (ftick->tk_ms_type) {

    case FT_M_FIOV:
        buf[0]    = ftick->tk_ms_fiov.base;
        buflen[0] = ftick->tk_ms_fiov.len;
        break;

    case FT_M_BUF:
        buf[0]    = ftick->tk_ms_fiov.base;
        buflen[0] = ftick->tk_ms_fiov.len;
        buf[1]    = ftick->tk_ms_bufdata;
        buflen[1] = ftick->tk_ms_bufsize;
        break;

    default:
        panic("MacFUSE: unknown message type for ticket %p", ftick);
    }

    for (i = 0; buf[i]; i++) {
        if (uio_resid(uio) < buflen[i]) {
            data->dataflags |= FSESS_DEAD;
            err = ENODEV;
            break;
        }

        err = uiomove(buf[i], buflen[i], uio);

        if (err) {
            break;
        }
    }

    /*
     * The FORGET message is an example of a ticket that has explicitly
     * been invalidated by the sender. The sender is not expecting or wanting
     * a reply, so he sets the FT_INVALID bit in the ticket.
     */
   
    fuse_ticket_drop_invalid(ftick);

    return (err);
}

int
fuse_device_write(dev_t dev, uio_t uio, __unused int ioflag)
{
    int err = 0, found = 0;

    struct fuse_device    *fdev;
    struct fuse_data      *data;
    struct fuse_ticket    *ftick;
    struct fuse_ticket    *x_ftick;
    struct fuse_out_header ohead;

    fuse_trace_printf_func();

    fdev = FUSE_DEVICE_FROM_UNIT_FAST(minor(dev));
    if (!fdev) {
        return ENXIO;
    }

    if (uio_resid(uio) < sizeof(struct fuse_out_header)) {
        return (EINVAL);
    }

    if ((err = uiomove((caddr_t)&ohead, sizeof(struct fuse_out_header), uio))
        != 0) {
        return (err);
    }

    /* begin audit */

    if (uio_resid(uio) + sizeof(struct fuse_out_header) != ohead.len) {
        IOLog("MacFUSE: message body size does not match that in the header\n");
        return (EINVAL); 
    }   

    if (uio_resid(uio) && ohead.error) {
        IOLog("MacFUSE: non-zero error for a message with a body\n");
        return (EINVAL);
    }

    ohead.error = -(ohead.error);

    /* end audit */

    data = fdev->data;

    fuse_lck_mtx_lock(data->aw_mtx);

    TAILQ_FOREACH_SAFE(ftick, &data->aw_head, tk_aw_link, x_ftick) {
        if (ftick->tk_unique == ohead.unique) {
            found = 1;
            fuse_aw_remove(ftick);
            break;
        }
    }

    fuse_lck_mtx_unlock(data->aw_mtx);

    if (found) {
        if (ftick->tk_aw_handler) {
            memcpy(&ftick->tk_aw_ohead, &ohead, sizeof(ohead));
            err = ftick->tk_aw_handler(ftick, uio);
        } else {
            fuse_ticket_drop(ftick);
            return (err);
        }
    } else {
        debug_printf("no handler for this response\n");
    }

    return (err);
}

int
fuse_devices_start(void)
{
    int i = 0;

    fuse_trace_printf_func();

    bzero((void *)fuse_device_table, sizeof(fuse_device_table));

    if ((fuse_cdev_major = cdevsw_add(-1, &fuse_device_cdevsw)) == -1) {
        goto error;
    }

    for (i = 0; i < FUSE_NDEVICES; i++) {

        dev_t dev = makedev(fuse_cdev_major, i);
        fuse_device_table[i].cdev = devfs_make_node(dev,
                                                   DEVFS_CHAR,
                                                   UID_ROOT,
                                                   GID_OPERATOR,
                                                   0666,
                                                   "fuse%d",
                                                   i);
        if (fuse_device_table[i].cdev == NULL) {
            goto error;
        }

        fuse_device_table[i].data     = NULL;
        fuse_device_table[i].dev      = dev;
        fuse_device_table[i].pid      = -1;
        fuse_device_table[i].random   = 0;
        fuse_device_table[i].usecount = 0;
        fuse_device_table[i].mtx      = lck_mtx_alloc_init(fuse_lock_group,
                                                           fuse_lock_attr);
    }

    fuse_interface_available = TRUE;

    return KERN_SUCCESS;

error:
    for (--i; i >= 0; i--) {
        devfs_remove(fuse_device_table[i].cdev);
        fuse_device_table[i].cdev = NULL;
        fuse_device_table[i].dev  = 0;
        lck_mtx_free(fuse_device_table[i].mtx, fuse_lock_group);
    }

    (void)cdevsw_remove(fuse_cdev_major, &fuse_device_cdevsw);
    fuse_cdev_major = -1;

    return KERN_FAILURE;
}

int
fuse_devices_stop(void)
{
    int i, ret;

    fuse_trace_printf_func();

    fuse_interface_available = FALSE;

    FUSE_DEVICE_GLOBAL_LOCK();

    if (fuse_cdev_major == -1) {
        FUSE_DEVICE_GLOBAL_UNLOCK();
        return KERN_SUCCESS;
    }

    for (i = 0; i < FUSE_NDEVICES; i++) {

        char p_comm[MAXCOMLEN + 1] = { '?', '\0' };

        if (fuse_device_table[i].usecount != 0) {
            fuse_interface_available = TRUE;
            FUSE_DEVICE_GLOBAL_UNLOCK();
            proc_name(fuse_device_table[i].pid, p_comm, MAXCOMLEN + 1);
            IOLog("MacFUSE: /dev/fuse%d is still active (pid=%d %s)\n",
                  i, fuse_device_table[i].pid, p_comm);
            return KERN_FAILURE;
        }

        if (fuse_device_table[i].data != NULL) {
            fuse_interface_available = TRUE;
            FUSE_DEVICE_GLOBAL_UNLOCK();
            proc_name(fuse_device_table[i].pid, p_comm, MAXCOMLEN + 1);
            /* The pid can't possibly be active here. */
            IOLog("MacFUSE: /dev/fuse%d has a lingering mount (pid=%d, %s)\n",
                  i, fuse_device_table[i].pid, p_comm);
            return KERN_FAILURE;
        }
    }

    /* No device is in use. */

    for (i = 0; i < FUSE_NDEVICES; i++) {
        devfs_remove(fuse_device_table[i].cdev);
        lck_mtx_free(fuse_device_table[i].mtx, fuse_lock_group);
        fuse_device_table[i].cdev   = NULL;
        fuse_device_table[i].dev    = 0;
        fuse_device_table[i].pid    = -1;
        fuse_device_table[i].random = 0;
        fuse_device_table[i].mtx    = NULL;
    }

    ret = cdevsw_remove(fuse_cdev_major, &fuse_device_cdevsw);
    if (ret != fuse_cdev_major) {
        IOLog("MacFUSE: fuse_cdev_major != return from cdevsw_remove()\n");
    }

    fuse_cdev_major = -1;

    FUSE_DEVICE_GLOBAL_UNLOCK();

    return KERN_SUCCESS;
}

/* Control/Debug Utilities */

int
fuse_device_ioctl(dev_t dev, u_long cmd, caddr_t udata,
                  __unused int flags, __unused proc_t proc)
{
    int ret = EINVAL;
    struct fuse_device *fdev;
    struct fuse_data   *data;

    fuse_trace_printf_func();

    fdev = FUSE_DEVICE_FROM_UNIT_FAST(minor(dev));
    if (!fdev) {
        return ENXIO;
    }

    FUSE_DEVICE_LOCAL_LOCK(fdev);

    data = fdev->data;
    if (!data) {
        FUSE_DEVICE_LOCAL_UNLOCK(fdev);
        return ENXIO;
    }

    switch (cmd) {
    case FUSEDEVIOCSETIMPLEMENTEDBITS:
        ret = fuse_set_implemented_custom(data, *(uint64_t *)udata);
        break;

    case FUSEDEVIOCGETHANDSHAKECOMPLETE:
        if (data->mount_state == FM_NOTMOUNTED) {
            ret = ENXIO;
        } else {
            *(u_int32_t *)udata = (data->dataflags & FSESS_INITED);
            ret = 0;
        }
        break;

    case FUSEDEVIOCSETDAEMONDEAD:
        fdata_dead_set(data);
        fuse_lck_mtx_lock(data->timeout_mtx);
        data->timeout_status = FUSE_DAEMON_TIMEOUT_DEAD;
        fuse_lck_mtx_unlock(data->timeout_mtx);
        ret = 0;
        break;

    case FUSEDEVIOCGETRANDOM:
        *(u_int32_t *)udata = fdev->random;
        ret = 0;
        break;

    /*
     * In the user-space library, you can get the inode number from a path
     * by using something like:
     *
     * fuse_ino_t
     * find_fuse_inode_for_path(const char *path)
     * {
     *     struct fuse_context *context = fuse_get_context();
     *     struct fuse *the_fuse = context->fuse;
     *     struct node *node find_node(the_fuse, FUSE_ROOT_ID, path);
     *     if (!node) {
     *         return 0;
     *     }
     *     return (node->nodeid);
     * }
     */
    case FUSEDEVIOCALTERVNODEFORINODE:
        {
            HNodeRef hn;
            vnode_t  vn;
            dev_t    dummy_device = (dev_t)data->fdev;

            struct fuse_avfi_ioctl *avfi = (struct fuse_avfi_ioctl *)udata;

            ret = (int)HNodeLookupRealQuickIfExists(dummy_device,
                                                    (ino_t)avfi->inode,
                                                    0, /* fork index */
                                                    &hn,
                                                    &vn);
            if (ret) {
                break;
            }

            assert(vn != NULL);

            ret = fuse_internal_ioctl_avfi(vn, (vfs_context_t)0, avfi);

            if (vn) {
                vnode_put(vn);
            }
        }
        break;

    default:
        break;
        
    }

    FUSE_DEVICE_LOCAL_UNLOCK(fdev);

    return ret;
}

int
fuse_device_kill(int unit, struct proc *p)
{
    int error = ENOENT;
    struct fuse_device *fdev;

    if ((unit < 0) || (unit >= FUSE_NDEVICES)) {
        return EINVAL;
    }

    fdev = FUSE_DEVICE_FROM_UNIT_FAST(unit);
    if (!fdev) {
        return ENOENT;
    }

    FUSE_DEVICE_LOCAL_LOCK(fdev);

    if (fdev->data) {
        error = EPERM;
        if (p) {
            kauth_cred_t request_cred = proc_ucred(p);
            if ((kauth_cred_getuid(request_cred) == 0) ||
                (fuse_match_cred(fdev->data->daemoncred, request_cred) == 0)) {

                /* The following can block. */
                fdata_dead_set(fdev->data);

                error = 0;

                fuse_lck_mtx_lock(fdev->data->aw_mtx);
                {
                    struct fuse_ticket *ftick;
                    while ((ftick = fuse_aw_pop(fdev->data))) {
                        fuse_lck_mtx_lock(ftick->tk_aw_mtx);
                        fticket_set_answered(ftick);
                        ftick->tk_aw_errno = ENOTCONN;
                        fuse_wakeup(ftick);
                        fuse_lck_mtx_unlock(ftick->tk_aw_mtx);
                    }
                }
                fuse_lck_mtx_unlock(fdev->data->aw_mtx);
            }
        }
    }

    FUSE_DEVICE_LOCAL_UNLOCK(fdev);

    return error;
}

int
fuse_device_print_vnodes(int unit_flags, struct proc *p)
{
    int error = ENOENT;
    struct fuse_device *fdev;

    int unit = unit_flags;

    if ((unit < 0) || (unit >= FUSE_NDEVICES)) {
        return EINVAL;
    }

    fdev = FUSE_DEVICE_FROM_UNIT_FAST(unit);
    if (!fdev) {
        return ENOENT;
    }

    FUSE_DEVICE_LOCAL_LOCK(fdev);

    if (fdev->data) {

        mount_t mp = fdev->data->mp;

        if (vfs_busy(mp, LK_NOWAIT)) {
            FUSE_DEVICE_LOCAL_UNLOCK(fdev);
            return EBUSY;
        }
        
        error = EPERM;
        if (p) {
            kauth_cred_t request_cred = proc_ucred(p);
            if ((kauth_cred_getuid(request_cred) == 0) ||
                (fuse_match_cred(fdev->data->daemoncred, request_cred) == 0)) {
                fuse_internal_print_vnodes(fdev->data->mp);
                error = 0;
            }
        }

        vfs_unbusy(mp);
    }

    FUSE_DEVICE_LOCAL_UNLOCK(fdev);

    return error;
}
