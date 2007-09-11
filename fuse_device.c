/*
 * Copyright (C) 2006 Google. All Rights Reserved.
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

#define TAILQ_FOREACH_SAFE(var, head, field, tvar)           \
        for ((var) = TAILQ_FIRST((head));                    \
            (var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
            (var) = (tvar))

static int    fuse_cdev_major          = -1;
static UInt32 fuse_interface_available = FALSE;

struct fuse_softc {
    int               usecount;
    pid_t             pid;
    dev_t             dev;
    void             *cdev;
    struct fuse_data *data;
};

struct fuse_softc fuse_softc_table[FUSE_NDEVICES];

#define FUSE_SOFTC_FROM_UNIT_FAST(u) (fuse_softc_t)&(fuse_softc_table[(u)])

int
fuse_devices_kill(int unit, struct proc *p)
{
    int error = ENOENT;
    struct fuse_softc *fdev;

    if ((unit < 0) || (unit >= FUSE_NDEVICES)) {
        return EINVAL;
    }

    fdev = FUSE_SOFTC_FROM_UNIT_FAST(unit);
    if (!fdev) {
        return ENOENT;
    }

    FUSE_DEVICE_LOCK();

    if (fdev->data) {
        error = EPERM;
        if (p) {
            kauth_cred_t request_cred = proc_ucred(p);
            if ((kauth_cred_getuid(request_cred) == 0) ||
                (fuse_match_cred(fdev->data->daemoncred, request_cred) == 0)) {
                FUSE_DEVICE_UNLOCK();
                /* The following can block. */
                fdata_kick_set(fdev->data);
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
    } else {
        FUSE_DEVICE_UNLOCK();
    }

    return error;
}

int
fuse_devices_print_vnodes(int unit_flags, struct proc *p)
{
    int error = ENOENT;
    struct fuse_softc *fdev;

    int unit = unit_flags;

    if ((unit < 0) || (unit >= FUSE_NDEVICES)) {
        return EINVAL;
    }

    fdev = FUSE_SOFTC_FROM_UNIT_FAST(unit);
    if (!fdev) {
        return ENOENT;
    }

    FUSE_DEVICE_LOCK();

    if (fdev->data) {
        error = EPERM;
        if (p) {
            kauth_cred_t request_cred = proc_ucred(p);
            if ((kauth_cred_getuid(request_cred) == 0) ||
                (fuse_match_cred(fdev->data->daemoncred, request_cred) == 0)) {
                fuse_internal_print_vnodes(fdev->data->mp);
                error = 0;
            }
        }
    }

    FUSE_DEVICE_UNLOCK();

    return error;
}

fuse_softc_t
fuse_softc_get(dev_t dev)
{
    int unit = minor(dev);

    if ((unit < 0) || (unit >= FUSE_NDEVICES)) {
        return (fuse_softc_t)0;
    }

    return FUSE_SOFTC_FROM_UNIT_FAST(unit);
}

/* Must be called under lock. */
__inline__
int
fuse_softc_get_usecount(fuse_softc_t fdev)
{
    if (!fdev) {
        return -1;
    }

    return fdev->usecount;
}

/* Must be called under lock. */
__inline__
struct fuse_data *
fuse_softc_get_data(fuse_softc_t fdev)
{
    if (fdev) {
       return fdev->data;
    }

    return NULL;
}

/* Must be called under lock. */
__inline__
void
fuse_softc_set_data(fuse_softc_t fdev, struct fuse_data *data)
{
    if (!fdev) {
       return;
    }

    fdev->data = data;
}

/* Must be called under lock. */
dev_t
fuse_softc_get_dev(fuse_softc_t fdev)
{
    if (fdev) {
        return 0;
    }

    return fdev->dev;
}

/* Must be called under lock. */
__inline__
void
fuse_softc_close_finalize(fuse_softc_t fdev)
{
    if (fdev) {
        fdev->data = NULL;
        fdev->pid = -1;
        fdev->usecount--;
    }
}

static int
fuse_device_enodev(void)
{
    return ENODEV;
}

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
    /* stop     */ (d_stop_t *)&fuse_device_enodev,
    /* reset    */ (d_reset_t *)&fuse_device_enodev,
    /* ttys     */ 0,
    /* select   */ (d_select_t *)&fuse_device_enodev,
    /* mmap     */ (d_mmap_t *)&fuse_device_enodev,
    /* strategy */ (d_strategy_t *)&fuse_device_enodev,
    /* getc     */ (d_getc_t *)&fuse_device_enodev,
    /* putc     */ (d_putc_t *)&fuse_device_enodev,
    /* flags    */ D_TTY,
};

int
fuse_device_open(dev_t dev, __unused int flags, __unused int devtype,
                 struct proc *p)
{
    int unit;
    struct fuse_softc *fdev;
    struct fuse_data  *fdata;

    fuse_trace_printf_func();

    if (fuse_interface_available == FALSE) {
        return ENOENT;
    }

    unit = minor(dev);
    if (unit >= FUSE_NDEVICES) {
        FUSE_DEVICE_UNLOCK();
        return ENOENT;
    }

    fdev = FUSE_SOFTC_FROM_UNIT_FAST(unit);
    if (!fdev) {
        FUSE_DEVICE_UNLOCK();
        IOLog("MacFUSE: device with no softc!\n");
        return ENXIO;
    }

    FUSE_DEVICE_LOCK();

    if (fdev->usecount != 0) {
        FUSE_DEVICE_UNLOCK();
        return EBUSY;
    }

    fdev->usecount++;

    FUSE_DEVICE_UNLOCK();

    /* Could block. */
    fdata = fdata_alloc(fdev, p);

    FUSE_DEVICE_LOCK();

    if (fdev->data) {
        /*
         * This slot isn't currently open by a user daemon. However, it was
         * used earlier for a mount that's still lingering, even though the
         * user daemon is dead.
         */

        fdev->usecount--;

        FUSE_DEVICE_UNLOCK();

        fdata_destroy(fdata);

        return EBUSY;
    } else {
        fdata->dataflags |= FSESS_OPENED;
        fdev->data = fdata;
        fdev->pid = proc_pid(p);
    }       

    FUSE_DEVICE_UNLOCK();

    return KERN_SUCCESS;
}

int
fuse_device_close(dev_t dev, __unused int flags, __unused int devtype,
                  __unused struct proc *p)
{
    int unit, skip_destroy = 0;
    struct fuse_softc *fdev;
    struct fuse_data  *data;

    fuse_trace_printf_func();

    unit = minor(dev);
    if (unit >= FUSE_NDEVICES) {
        return ENOENT;
    }

    fdev = FUSE_SOFTC_FROM_UNIT_FAST(unit);
    if (!fdev) {
        return ENXIO;
    }

    data = fdev->data;
    if (!data) {
        panic("MacFUSE: no softc data upon device close");
    }

    fdata_kick_set(data);

    FUSE_DEVICE_LOCK();

    data->dataflags &= ~FSESS_OPENED;

    FUSE_DEVICE_UNLOCK();

    fuse_lck_mtx_lock(data->aw_mtx);

    FUSE_DEVICE_LOCK();

    if (data->mount_state == FM_MOUNTED) {
        struct fuse_ticket *ftick;

        skip_destroy = 1;

        FUSE_DEVICE_UNLOCK();

        while ((ftick = fuse_aw_pop(data))) {
            fuse_lck_mtx_lock(ftick->tk_aw_mtx);
            fticket_set_answered(ftick);
            ftick->tk_aw_errno = ENOTCONN;
            fuse_wakeup(ftick);
            fuse_lck_mtx_unlock(ftick->tk_aw_mtx);
        }

        fuse_lck_mtx_unlock(data->aw_mtx);
    } else {
        FUSE_DEVICE_UNLOCK();
    }

    FUSE_DEVICE_LOCK();

    if (!skip_destroy) {
        fdev->data = NULL;
        fdev->pid = -1;
        fdev->usecount--;
    }

    FUSE_DEVICE_UNLOCK();

    if (!skip_destroy) {
        fdata_destroy(data);
    }

    return KERN_SUCCESS;
}

int
fuse_device_read(dev_t dev, uio_t uio, __unused int ioflag)
{
    int i, err = 0;
    void *buf[] = { NULL, NULL, NULL };
    int buflen[3];

    struct fuse_softc  *fdev;
    struct fuse_data   *data;
    struct fuse_ticket *ftick;

    fuse_trace_printf_func();

    fdev = FUSE_SOFTC_FROM_UNIT_FAST(minor(dev));
    if (!fdev) {
        return ENXIO;
    }

    data = fdev->data;

    fuse_lck_mtx_lock(data->ms_mtx);

    /* The read loop (outgoing messages to the user daemon). */

again:
    if (fdata_kick_get(data)) {
        fuse_lck_mtx_unlock(data->ms_mtx);
        return ENODEV;
    }

    if (!(ftick = fuse_ms_pop(data))) {
        err = fuse_msleep(data, data->ms_mtx, PCATCH, "fu_msg", 0);
        if (err != 0) {
            fuse_lck_mtx_unlock(data->ms_mtx);
            return (fdata_kick_get(data) ? ENODEV : err);
        }
        ftick = fuse_ms_pop(data);
    }

    if (!ftick) {
        goto again;
    }

    fuse_lck_mtx_unlock(data->ms_mtx);

    if (fdata_kick_get(data)) {
         if (ftick) {
             fuse_ticket_drop_invalid(ftick);
         }
         return ENODEV;
    }

    switch (ftick->tk_ms_type) {

    case FT_M_FIOV:
        buf[0] = ftick->tk_ms_fiov.base;
        buflen[0] =  ftick->tk_ms_fiov.len;
        break;

    case FT_M_BUF:
        buf[0] = ftick->tk_ms_fiov.base;
        buflen[0] =  ftick->tk_ms_fiov.len;
        buf[1] = ftick->tk_ms_bufdata;
        buflen[1] =  ftick->tk_ms_bufsize;
        break;

    default:
        panic("MacFUSE: unknown message type for ticket %p", ftick);
    }

    for (i = 0; buf[i]; i++) {
        if (uio_resid(uio) < buflen[i]) {
            data->dataflags |= FSESS_KICK;
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

/*
 * XXX: This function needs locking in many places!
 */
int
fuse_device_ioctl(dev_t dev, u_long cmd, caddr_t udata,
                  __unused int flags, __unused proc_t proc)
{
    int ret = EINVAL;
    struct fuse_softc *fdev;
    struct fuse_data  *data;

    fdev = FUSE_SOFTC_FROM_UNIT_FAST(minor(dev));
    if (!fdev) {
        return ENXIO;
    }

    data = fdev->data;
    if (!data) {
        return ENXIO;
    }

    switch (cmd) {
    case FUSEDEVIOCSETIMPLEMENTEDBITS:
        ret = fuse_set_noimplflags(data, *(uint64_t *)udata);
        break;

    case FUSEDEVIOCGETHANDSHAKECOMPLETE:
        if (data->mount_state == FM_NOTMOUNTED) {
            return ENXIO;
        }
        *(u_int32_t *)udata = (data->dataflags & FSESS_INITED);
        ret = 0;
        break;

    case FUSEDEVIOCSETDAEMONDEAD:
        fdata_kick_set(data);
        fuse_lck_mtx_lock(data->timeout_mtx);
        data->timeout_status = FUSE_DAEMON_TIMEOUT_DEAD;
        fuse_lck_mtx_unlock(data->timeout_mtx);
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
                return ret;
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

    return ret;
}

static __inline__
int
fuse_ohead_audit(struct fuse_out_header *ohead, uio_t uio)
{
    if (uio_resid(uio) + sizeof(struct fuse_out_header) != ohead->len) {
        IOLog("MacFUSE: message body size does not match that in the header\n");
        return (EINVAL); 
    }   
    
    if (uio_resid(uio) && ohead->error) {
        IOLog("MacFUSE: non-zero error for a message with a body\n");
        return (EINVAL);
    }

    ohead->error = -(ohead->error);

    return (0);
}   

int
fuse_device_write(dev_t dev, uio_t uio, __unused int ioflag)
{
    int err = 0, found = 0;
    struct fuse_out_header ohead;
    struct fuse_softc  *fdev;
    struct fuse_data   *data;
    struct fuse_ticket *ftick, *x_ftick;

    fuse_trace_printf_func();

    fdev = FUSE_SOFTC_FROM_UNIT_FAST(minor(dev));
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

    if ((err = fuse_ohead_audit(&ohead, uio))) {
        return (err);
    }

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

    bzero((void *)fuse_softc_table, sizeof(fuse_softc_table));

    if ((fuse_cdev_major = cdevsw_add(-1, &fuse_device_cdevsw)) == -1) {
        goto error;
    }

    for (i = 0; i < FUSE_NDEVICES; i++) {

        dev_t dev = makedev(fuse_cdev_major, i);
        fuse_softc_table[i].cdev = devfs_make_node(dev,
                                                   DEVFS_CHAR,
                                                   UID_ROOT,
                                                   GID_OPERATOR,
                                                   0666,
                                                   "fuse%d",
                                                   i);
        if (fuse_softc_table[i].cdev == NULL) {
            goto error;
        }

        fuse_softc_table[i].data     = NULL;
        fuse_softc_table[i].dev      = dev;
        fuse_softc_table[i].pid      = -1;
        fuse_softc_table[i].usecount = 0;
    }

    fuse_interface_available = TRUE;

    return KERN_SUCCESS;

error:
    for (--i; i >= 0; i--) {
        devfs_remove(fuse_softc_table[i].cdev);
        fuse_softc_table[i].cdev = NULL;
        fuse_softc_table[i].dev  = 0;
    }

    (void)cdevsw_remove(fuse_cdev_major, &fuse_device_cdevsw);
    fuse_cdev_major = -1;

    return KERN_FAILURE;
}

int
fuse_devices_stop(void)
{
    int i, ret;

    fuse_interface_available = FALSE;

    FUSE_DEVICE_LOCK();

    if (fuse_cdev_major == -1) {
        FUSE_DEVICE_UNLOCK();
        return KERN_SUCCESS;
    }

    for (i = 0; i < FUSE_NDEVICES; i++) {

        char p_comm[MAXCOMLEN + 1] = { '?', '\0' };

        if (fuse_softc_table[i].usecount != 0) {
            fuse_interface_available = TRUE;
            FUSE_DEVICE_UNLOCK();
            proc_name(fuse_softc_table[i].pid, p_comm, MAXCOMLEN + 1);
            IOLog("MacFUSE: /dev/fuse%d is still active (pid=%d %s)\n",
                  i, fuse_softc_table[i].pid, p_comm);
            return KERN_FAILURE;
        }

        if (fuse_softc_table[i].data != NULL) {
            fuse_interface_available = TRUE;
            FUSE_DEVICE_UNLOCK();
            proc_name(fuse_softc_table[i].pid, p_comm, MAXCOMLEN + 1);
            /* The pid can't possibly be active here. */
            IOLog("MacFUSE: /dev/fuse%d has a lingering mount (pid=%d, %s)\n",
                  i, fuse_softc_table[i].pid, p_comm);
            return KERN_FAILURE;
        }
    }

    /* No device is in use. */

    for (i = 0; i < FUSE_NDEVICES; i++) {
        devfs_remove(fuse_softc_table[i].cdev);
        fuse_softc_table[i].cdev = NULL;
        fuse_softc_table[i].dev  = 0;
        fuse_softc_table[i].pid  = -1;
    }

    ret = cdevsw_remove(fuse_cdev_major, &fuse_device_cdevsw);
    if (ret != fuse_cdev_major) {
        IOLog("MacFUSE: fuse_cdev_major != return from cdevsw_remove()\n");
    }

    fuse_cdev_major = -1;

    FUSE_DEVICE_UNLOCK();

    return KERN_SUCCESS;
}
