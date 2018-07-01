/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2010 Tuxera Inc.
 * Copyright (c) 2013-2016 Benjamin Fleischer
 * All rights reserved.
 */

#include "fuse_ipc.h"

#include "fuse_internal.h"
#include "fuse_kludges.h"

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK
    #if M_OSXFUSE_ENABLE_BIG_LOCK
        #include "fuse_biglock_vnops.h"
    #endif
    #include "fuse_notify.h"
#endif

#include <sys/vm.h>

#if M_OSXFUSE_ENABLE_DSELECT
    #include <sys/select.h>
#endif

static struct fuse_ticket *fticket_alloc(struct fuse_data *data);
static void fticket_refresh(struct fuse_ticket *ftick);
static void fticket_destroy(struct fuse_ticket *ftick);
static int fticket_wait_answer(struct fuse_ticket *ftick);
FUSE_INLINE int fticket_aw_pull_uio(struct fuse_ticket *ftick,
                                               uio_t uio);
FUSE_INLINE void fuse_push_freeticks(struct fuse_ticket *ftick);

FUSE_INLINE struct fuse_ticket *fuse_pop_freeticks(struct fuse_data *data);

FUSE_INLINE void fuse_push_allticks(struct fuse_ticket *ftick);
FUSE_INLINE void fuse_remove_allticks(struct fuse_ticket *ftick);
static struct fuse_ticket *fuse_pop_allticks(struct fuse_data *data);

static int fuse_body_audit(struct fuse_ticket *ftick, size_t blen);
FUSE_INLINE void fuse_setup_ihead(struct fuse_in_header *ihead,
                                  struct fuse_ticket    *ftick,
                                  uint64_t               nid,
                                  enum fuse_opcode       op,
                                  size_t                 blen,
                                  vfs_context_t          context);

static fuse_handler_t fuse_standard_handler;

void
fiov_init(struct fuse_iov *fiov, size_t size)
{
    size_t msize = FU_AT_LEAST(size);

    fiov->len = 0;

    fiov->base = FUSE_OSMalloc(msize, fuse_malloc_tag);
    if (!fiov->base) {
        panic("osxfuse: OSMalloc failed in fiov_init");
    }

    FUSE_OSAddAtomic(1, (SInt32 *)&fuse_iov_current);

    bzero(fiov->base, msize);

    fiov->allocated_size = msize;
    fiov->credit = fuse_iov_credit;
}

void
fiov_teardown(struct fuse_iov *fiov)
{
    FUSE_OSFree(fiov->base, fiov->allocated_size, fuse_malloc_tag);
    fiov->allocated_size = 0;

    FUSE_OSAddAtomic(-1, (SInt32 *)&fuse_iov_current);
}

void
fiov_adjust(struct fuse_iov *fiov, size_t size)
{
    if (fiov->allocated_size < size ||
        (fiov->allocated_size - size > fuse_iov_permanent_bufsize &&
             --fiov->credit < 0)) {

        fiov->base = FUSE_OSRealloc_nocopy(fiov->base, fiov->allocated_size,
                                           FU_AT_LEAST(size));
        if (!fiov->base) {
            panic("osxfuse: realloc failed");
        }

        fiov->allocated_size = FU_AT_LEAST(size);
        fiov->credit = fuse_iov_credit;
    }

    fiov->len = size;
}

int
fiov_adjust_canfail(struct fuse_iov *fiov, size_t size)
{
    if (fiov->allocated_size < size ||
        (fiov->allocated_size - size > fuse_iov_permanent_bufsize &&
             --fiov->credit < 0)) {

        void *tmpbase = NULL;

        tmpbase = FUSE_OSRealloc_nocopy_canfail(fiov->base,
                                                fiov->allocated_size,
                                                FU_AT_LEAST(size));
        if (!tmpbase) {
            return ENOMEM;
        }

        fiov->base = tmpbase;
        fiov->allocated_size = FU_AT_LEAST(size);
        fiov->credit = fuse_iov_credit;
    }

    fiov->len = size;

    return 0;
}

void
fiov_refresh(struct fuse_iov *fiov)
{
    bzero(fiov->base, fiov->len);
    fiov_adjust(fiov, 0);
}

static struct fuse_ticket *
fticket_alloc(struct fuse_data *data)
{
    struct fuse_ticket *ftick;

    ftick = (struct fuse_ticket *)FUSE_OSMalloc(sizeof(struct fuse_ticket),
                                                fuse_malloc_tag);
    if (!ftick) {
        panic("osxfuse: OSMalloc failed in fticket_alloc");
    }

    FUSE_OSAddAtomic(1, (SInt32 *)&fuse_tickets_current);

    bzero(ftick, sizeof(struct fuse_ticket));

    data->ticketer++;
    if (data->ticketer == 0) {
        /* Unique 0 is reserved for notifications. */
        data->ticketer = 1;
    }

    ftick->tk_unique = data->ticketer;
    ftick->tk_data = data;

    fiov_init(&ftick->tk_ms_fiov, sizeof(struct fuse_in_header));
    ftick->tk_ms_type = FT_M_FIOV;

    ftick->tk_mtx = lck_mtx_alloc_init(fuse_lock_group, fuse_lock_attr);
    fiov_init(&ftick->tk_aw_fiov, 0);
    ftick->tk_aw_type = FT_A_FIOV;

    return ftick;
}

FUSE_INLINE
void
fticket_refresh(struct fuse_ticket *ftick)
{
    fiov_refresh(&ftick->tk_ms_fiov);
    ftick->tk_ms_bufdata = NULL;
    ftick->tk_ms_bufsize = 0;
    ftick->tk_ms_type = FT_M_FIOV;

    bzero(&ftick->tk_aw_ohead, sizeof(struct fuse_out_header));

    fiov_refresh(&ftick->tk_aw_fiov);
    ftick->tk_aw_errno = 0;
    ftick->tk_aw_bufdata = NULL;
    ftick->tk_aw_bufsize = 0;
    ftick->tk_aw_type = FT_A_FIOV;

    ftick->tk_flag = 0;
#ifdef FUSE_TRACE_TICKET
    ftick->tk_age++;
#endif
    ftick->tk_interrupt = NULL;
}

static void
fticket_destroy(struct fuse_ticket *ftick)
{
    fiov_teardown(&ftick->tk_ms_fiov);

    lck_mtx_free(ftick->tk_mtx, fuse_lock_group);
    ftick->tk_mtx = NULL;
    fiov_teardown(&ftick->tk_aw_fiov);

    FUSE_OSFree(ftick, sizeof(struct fuse_ticket), fuse_malloc_tag);

    FUSE_OSAddAtomic(-1, (SInt32 *)&fuse_tickets_current);
}

static int
fticket_wait_answer(struct fuse_ticket *ftick)
{
    int err = 0;
    int err_interrupt = 0;
    struct fuse_data *data;
    int pri;
    bool remove_callback = true;

    fuse_lck_mtx_lock(ftick->tk_mtx);

    if (fticket_answered(ftick)) {
        goto out;
    }

    data = ftick->tk_data;
    pri = PCATCH;

restart:
    if (fdata_dead_get(data)) {
        fticket_set_answered(ftick);
        err = ENOTCONN;
        goto out;
    }

    err = fuse_msleep(ftick, ftick->tk_mtx, pri, "fu_ans",
                      data->daemon_timeout_p, data);

    if (err && fticket_answered(ftick)) {
        /*
         * msleep() has been interrupted or timed out after having received an
         * answer to this request, but before the handler had a chance to call
         * wakeup().
         */
        err = 0;
    }

    if (!err) {
        if (fticket_interrupted(ftick) && fticket_answered(ftick)
            && ftick->tk_aw_ohead.error == EINTR) {
            /*
             * The request has been interrupted in user space. It will not be
             * restarted automatically unless SA_RESTART is set and we return
             * ERESTART instead of EINTR. Therefore we need to restore the
             * original msleep error code.
             */
            ftick->tk_aw_ohead.error = err_interrupt;
        }
        goto out;
    }

    if (err == EWOULDBLOCK /* same as EAGAIN */) {
        if (fticket_interrupted(ftick)) {
            /*
             * We did not receive an answer within the timeout interval. At this
             * point the file system is considered dead.
             */
            fticket_set_answered(ftick);
            fdata_set_dead(data, false);

            err = ENOTCONN;
            goto out;

        } else {
            /*
             * Send an interrupt request to give the file system daemon a chance
             * to handle the timeout. If the daemon does not respond in time the
             * file system will be marked dead.
             */
            err = EINTR;
        }
    }

    if (err == EINTR || err == ERESTART) {
        if (!fticket_sent(ftick)
            && fuse_kludge_thread_should_abort(current_thread())) {
            fticket_set_answered(ftick);
            remove_callback = true;
            goto out;
        }

        if (!fticket_interrupted(ftick)) {
            fticket_set_interrupted(ftick);
            err_interrupt = err;

            if (fticket_sent(ftick)) {
                fuse_internal_interrupt_send(ftick);
            } else {
                /*
                 * The interrupt request will be queued in fuse_device_read()
                 * after the original request has been read by the daemon.
                 */
            }
        }

        if (fticket_sent(ftick)) {
            pri &= ~PCATCH;
        }
        goto restart;
    }

out:
    if (!fticket_answered(ftick)) {
        /*
         * We are no longer interested in an answer, therefore mark the ticket
         * as answered and remove its callback.
         */
        fticket_set_answered(ftick);
        remove_callback = true;

        if (!err) {
            IOLog("osxfuse: requester was woken up but still no answer");
            err = ENXIO;
        }
    }

    fuse_lck_mtx_unlock(ftick->tk_mtx);

    if (remove_callback) {
        fuse_remove_callback(ftick);
    }

    return err;
}

FUSE_INLINE
int
fticket_aw_pull_uio(struct fuse_ticket *ftick, uio_t uio)
{
    int err = 0;
    size_t len = (size_t)uio_resid(uio);

    if (len) {
        switch (ftick->tk_aw_type) {
        case FT_A_FIOV:
            err = fiov_adjust_canfail(fticket_resp(ftick), len);
            if (err) {
                fticket_set_kill(ftick);
                IOLog("osxfuse: failed to pull uio (error=%d)\n", err);
                break;
            }
            err = uiomove(fticket_resp(ftick)->base, (int)len, uio);
            if (err) {
                IOLog("osxfuse: FT_A_FIOV error is %d (%p, %ld, %p)\n",
                      err, fticket_resp(ftick)->base, len, uio);
            }
            break;

        case FT_A_BUF:
            ftick->tk_aw_bufsize = len;
            err = uiomove(ftick->tk_aw_bufdata, (int)len, uio);
            if (err) {
                IOLog("osxfuse: FT_A_BUF error is %d (%p, %ld, %p)\n",
                      err, ftick->tk_aw_bufdata, len, uio);
            }
            break;

        default:
            panic("osxfuse: unknown answer type for ticket %p", ftick);
        }
    }

    return err;
}

int
fticket_pull(struct fuse_ticket *ftick, uio_t uio)
{
    int err = 0;

    if (ftick->tk_aw_ohead.error) {
        return 0;
    }

    err = fuse_body_audit(ftick, (size_t)uio_resid(uio));
    if (!err) {
        err = fticket_aw_pull_uio(ftick, uio);
    }

    return err;
}

struct fuse_data *
fdata_alloc(struct proc *p)
{
    struct fuse_data *data;

    data = (struct fuse_data *)FUSE_OSMalloc(sizeof(struct fuse_data),
                                             fuse_malloc_tag);
    if (!data) {
        panic("osxfuse: OSMalloc failed in fdata_alloc");
    }

    bzero(data, sizeof(struct fuse_data));

    data->mp            = NULL;
    data->rootvp        = NULLVP;
    data->mount_state   = FM_NOTMOUNTED;
    data->daemoncred    = kauth_cred_proc_ref(p);
    data->dataflags     = 0;
    data->mountaltflags = 0ULL;
    data->noimplflags   = 0ULL;

    data->rwlock        = lck_rw_alloc_init(fuse_lock_group, fuse_lock_attr);
    data->ms_mtx        = lck_mtx_alloc_init(fuse_lock_group, fuse_lock_attr);
    data->aw_mtx        = lck_mtx_alloc_init(fuse_lock_group, fuse_lock_attr);
    data->ticket_mtx    = lck_mtx_alloc_init(fuse_lock_group, fuse_lock_attr);

    STAILQ_INIT(&data->ms_head);
    TAILQ_INIT(&data->aw_head);
    STAILQ_INIT(&data->freetickets_head);
    TAILQ_INIT(&data->alltickets_head);

    data->freeticket_counter = 0;
    data->deadticket_counter = 0;
    data->ticketer           = 1;

#if M_OSXFUSE_EXCPLICIT_RENAME_LOCK
    data->rename_lock = lck_rw_alloc_init(fuse_lock_group, fuse_lock_attr);
#endif

    data->abi_version.major = FUSE_KERNEL_VERSION;
    data->abi_version.minor = FUSE_KERNEL_MINOR_VERSION;

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK
#if M_OSXFUSE_ENABLE_BIG_LOCK
    data->biglock        = fuse_biglock_alloc();
#endif /* M_OSXFUSE_ENABLE_BIG_LOCK */
#endif /* M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */

    return data;
}

void
fdata_destroy(struct fuse_data *data)
{
    struct fuse_ticket *ftick;

    lck_mtx_free(data->ms_mtx, fuse_lock_group);
    data->ms_mtx = NULL;

    lck_mtx_free(data->aw_mtx, fuse_lock_group);
    data->aw_mtx = NULL;

    lck_mtx_free(data->ticket_mtx, fuse_lock_group);
    data->ticket_mtx = NULL;

#if M_OSXFUSE_EXPLICIT_RENAME_LOCK
    lck_rw_free(data->rename_lock, fuse_lock_group);
    data->rename_lock = NULL;
#endif

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK
#if M_OSXFUSE_ENABLE_BIG_LOCK
    fuse_biglock_free(data->biglock);
    data->biglock = NULL;
#endif /* M_OSXFUSE_ENABLE_BIG_LOCK */
#endif /* M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */

    while ((ftick = fuse_pop_allticks(data))) {
        fticket_destroy(ftick);
    }

    kauth_cred_unref(&(data->daemoncred));

    lck_rw_free(data->rwlock, fuse_lock_group);

    FUSE_OSFree(data, sizeof(struct fuse_data), fuse_malloc_tag);
}

bool
fdata_dead_get(struct fuse_data *data)
{
    return (data->dataflags & FSESS_DEAD);
}

bool
fdata_set_dead(struct fuse_data *data, bool fdev_locked)
{
    fuse_lck_mtx_lock(data->ms_mtx);
    if (fdata_dead_get(data)) {
        fuse_lck_mtx_unlock(data->ms_mtx);
        return false;
    }

    data->dataflags |= FSESS_DEAD;
    fuse_wakeup_one((caddr_t)data);
#if M_OSXFUSE_ENABLE_DSELECT
    selwakeup((struct selinfo*)&data->d_rsel);
#endif /* M_OSXFUSE_ENABLE_DSELECT */
    fuse_lck_mtx_unlock(data->ms_mtx);

    fuse_lck_mtx_lock(data->ticket_mtx);
    fuse_wakeup(&data->ticketer);
    fuse_lck_mtx_unlock(data->ticket_mtx);

    if (!fdev_locked) {
        fuse_device_lock(data->fdev);
    }
    if (data->mount_state == FM_MOUNTED) {
        /*
         * We might be called before the volume is mounted. In this case f_fsid
         * is not set and signaling VD_DEAD causes a page fault kernel panic on
         * OS X 10.8.
         */
        vfs_event_signal(&vfs_statfs(data->mp)->f_fsid, VQ_DEAD, 0);
    }
    if (!fdev_locked) {
        fuse_device_unlock(data->fdev);
    }

    return true;
}

FUSE_INLINE
int
fdata_wait_init_locked(struct fuse_data *data)
{
    if (!fdata_dead_get(data) && !(data->dataflags & FSESS_INITED)) {
        return fuse_msleep(&data->ticketer, data->ticket_mtx, PDROP, "fu_ini", 0, data);
    } else {
        fuse_lck_mtx_unlock(data->ticket_mtx);
        return 0;
    }
}

int
fdata_wait_init(struct fuse_data *data)
{
    int err = 0;

    fuse_lck_mtx_lock(data->ticket_mtx);
    err = fdata_wait_init_locked(data);

    /*
     * Note: fdata_wait_init_locked() drops ticket_mtx
     */

    return err;
}

FUSE_INLINE
void
fuse_push_freeticks(struct fuse_ticket *ftick)
{
    STAILQ_INSERT_TAIL(&ftick->tk_data->freetickets_head, ftick,
                       tk_freetickets_link);
    ftick->tk_data->freeticket_counter++;
}

FUSE_INLINE
struct fuse_ticket *
fuse_pop_freeticks(struct fuse_data *data)
{
    struct fuse_ticket *ftick;

    if ((ftick = STAILQ_FIRST(&data->freetickets_head))) {
        STAILQ_REMOVE_HEAD(&data->freetickets_head, tk_freetickets_link);
        data->freeticket_counter--;
    }

    if (STAILQ_EMPTY(&data->freetickets_head) &&
        (data->freeticket_counter != 0)) {
        panic("osxfuse: ticket count mismatch!");
    }

    return ftick;
}

FUSE_INLINE
void
fuse_push_allticks(struct fuse_ticket *ftick)
{
    TAILQ_INSERT_TAIL(&ftick->tk_data->alltickets_head, ftick,
                      tk_alltickets_link);
}

FUSE_INLINE
void
fuse_remove_allticks(struct fuse_ticket *ftick)
{
    ftick->tk_data->deadticket_counter++;
    TAILQ_REMOVE(&ftick->tk_data->alltickets_head, ftick, tk_alltickets_link);
}

static struct fuse_ticket *
fuse_pop_allticks(struct fuse_data *data)
{
    struct fuse_ticket *ftick;

    if ((ftick = TAILQ_FIRST(&data->alltickets_head))) {
        fuse_remove_allticks(ftick);
    }

    return ftick;
}

struct fuse_ticket *
fuse_ticket_fetch(struct fuse_data *data)
{
    int err = 0;
    struct fuse_ticket *ftick;

    fuse_lck_mtx_lock(data->ticket_mtx);

    if (data->freeticket_counter == 0) {
        fuse_lck_mtx_unlock(data->ticket_mtx);
        ftick = fticket_alloc(data);
        if (!ftick) {
            panic("osxfuse: ticket allocation failed");
        }
        fuse_lck_mtx_lock(data->ticket_mtx);
        fuse_push_allticks(ftick);
    } else {
        /* locked here */
        ftick = fuse_pop_freeticks(data);
        if (!ftick) {
            panic("osxfuse: no free ticket despite the counter's value");
        }
    }
    ftick->tk_ref_count = 1;

    if (data->ticketer > 2) {
        err = fdata_wait_init_locked(data);
    } else {
        if ((fuse_max_tickets != 0) &&
            ((data->ticketer - data->deadticket_counter) > fuse_max_tickets)) {
            err = 1;
        }
        fuse_lck_mtx_unlock(data->ticket_mtx);
    }

    if (err) {
        fdata_set_dead(data, false);
    }

    return ftick;
}

void
fuse_ticket_drop(struct fuse_ticket *ftick)
{
    bool die = false;

    fuse_lck_mtx_lock(ftick->tk_data->ticket_mtx);

    if (fuse_max_freetickets <= ftick->tk_data->freeticket_counter ||
        (ftick->tk_flag & FT_KILL)) {
        die = true;
    } else {
        fuse_lck_mtx_unlock(ftick->tk_data->ticket_mtx);
        fticket_refresh(ftick);
        fuse_lck_mtx_lock(ftick->tk_data->ticket_mtx);
    }

    /* locked here */

    if (die) {
        fuse_remove_allticks(ftick);
        fuse_lck_mtx_unlock(ftick->tk_data->ticket_mtx);
        fticket_destroy(ftick);
    } else {
        fuse_push_freeticks(ftick);
        fuse_lck_mtx_unlock(ftick->tk_data->ticket_mtx);
    }
}

void
fuse_ticket_kill(struct fuse_ticket *ftick)
{
    fuse_lck_mtx_lock(ftick->tk_data->ticket_mtx);
    fuse_remove_allticks(ftick);
    fuse_lck_mtx_unlock(ftick->tk_data->ticket_mtx);
    fticket_destroy(ftick);
}

void
fuse_insert_callback(struct fuse_ticket *ftick, fuse_handler_t *handler)
{
    if (fdata_dead_get(ftick->tk_data)) {
        return;
    }

    fuse_ticket_retain(ftick);
    ftick->tk_aw_handler = handler;

    fuse_lck_mtx_lock(ftick->tk_data->aw_mtx);
    fuse_aw_push(ftick);
    fuse_lck_mtx_unlock(ftick->tk_data->aw_mtx);
}

void
fuse_remove_callback(struct fuse_ticket *ftick)
{
    struct fuse_data *data = ftick->tk_data;
    struct fuse_ticket *curr;

    fuse_lck_mtx_lock(data->aw_mtx);
    TAILQ_FOREACH(curr, &data->aw_head, tk_aw_link) {
        if (curr == ftick) {
            fuse_aw_remove(curr);
            fuse_ticket_release(curr);
            break;
        }
    }
    fuse_lck_mtx_unlock(data->aw_mtx);
}

void
fuse_insert_message(struct fuse_ticket *ftick)
{
    if (ftick->tk_flag & FT_DIRTY) {
        panic("osxfuse: ticket reused without being refreshed");
    }

    if (fdata_dead_get(ftick->tk_data)) {
        return;
    }

    fuse_ticket_retain(ftick);
    ftick->tk_flag |= FT_DIRTY;

    fuse_lck_mtx_lock(ftick->tk_data->ms_mtx);
    fuse_ms_push(ftick);
    fuse_wakeup_one((caddr_t)ftick->tk_data);
#if M_OSXFUSE_ENABLE_DSELECT
    selwakeup((struct selinfo*)&ftick->tk_data->d_rsel);
#endif /* M_OSXFUSE_ENABLE_DSELECT */
    fuse_lck_mtx_unlock(ftick->tk_data->ms_mtx);
}

void
fuse_insert_message_head(struct fuse_ticket *ftick)
{
    if (ftick->tk_flag & FT_DIRTY) {
        panic("osxfuse: ticket reused without being refreshed");
    }

    if (fdata_dead_get(ftick->tk_data)) {
        return;
    }

    fuse_ticket_retain(ftick);
    ftick->tk_flag |= FT_DIRTY;

    fuse_lck_mtx_lock(ftick->tk_data->ms_mtx);
    fuse_ms_push_head(ftick);
    fuse_wakeup_one((caddr_t)ftick->tk_data);
#if M_OSXFUSE_ENABLE_DSELECT
    selwakeup((struct selinfo*)&ftick->tk_data->d_rsel);
#endif /* M_OSXFUSE_ENABLE_DSELECT */
    fuse_lck_mtx_unlock(ftick->tk_data->ms_mtx);
}

static int
fuse_body_audit(struct fuse_ticket *ftick, size_t blen)
{
#define FB_AUDIT_CASE_SIZE(OPCODE, CMP, SIZE) \
    case OPCODE:                              \
        err = (blen CMP (SIZE)) ? 0 : EINVAL; \
        break;

#define FB_AUDIT_CASE_OUT(OPCODE, NAME) \
    FB_AUDIT_CASE_SIZE(OPCODE, ==, NAME ## _sizeof(DATOI(data)))

#define FB_AUDIT_CASE_NO_OUT(OPCODE) FB_AUDIT_CASE_SIZE(OPCODE, ==, 0)

    int err = 0;
    struct fuse_data *data;
    enum fuse_opcode opcode;

    data = ftick->tk_data;
    opcode = fticket_opcode(ftick);

    switch (opcode) {
        FB_AUDIT_CASE_OUT(FUSE_LOOKUP, fuse_entry_out)

        case FUSE_FORGET:
            panic("osxfuse: a handler has been installed for FUSE_FORGET");
            break;

        FB_AUDIT_CASE_OUT(FUSE_GETATTR, fuse_attr_out)

        FB_AUDIT_CASE_OUT(FUSE_SETATTR, fuse_attr_out)

        FB_AUDIT_CASE_SIZE(FUSE_READLINK, <=, PAGE_SIZE)

        FB_AUDIT_CASE_OUT(FUSE_SYMLINK, fuse_entry_out)

        FB_AUDIT_CASE_OUT(FUSE_MKNOD, fuse_entry_out)

        FB_AUDIT_CASE_OUT(FUSE_MKDIR, fuse_entry_out)

        FB_AUDIT_CASE_NO_OUT(FUSE_UNLINK)

        FB_AUDIT_CASE_NO_OUT(FUSE_RMDIR)

        FB_AUDIT_CASE_NO_OUT(FUSE_RENAME)

        FB_AUDIT_CASE_OUT(FUSE_LINK, fuse_entry_out)

        FB_AUDIT_CASE_OUT(FUSE_OPEN, fuse_open_out)

        FB_AUDIT_CASE_SIZE(FUSE_READ, <=,
            ((struct fuse_read_in *)((char *)ftick->tk_ms_fiov.base +
                                     sizeof(struct fuse_in_header)))->size)

        FB_AUDIT_CASE_OUT(FUSE_WRITE, fuse_write_out)

        FB_AUDIT_CASE_OUT(FUSE_STATFS, fuse_statfs_out)

        FB_AUDIT_CASE_NO_OUT(FUSE_RELEASE)

        FB_AUDIT_CASE_NO_OUT(FUSE_FSYNC)

        case FUSE_SETXATTR:
            /* TBD */
            break;

        case FUSE_GETXATTR:
            /* TBD */
            break;

        case FUSE_LISTXATTR:
            /* TBD */
            break;

        case FUSE_REMOVEXATTR:
            /* TBD */
            break;

        FB_AUDIT_CASE_NO_OUT(FUSE_FLUSH)

        FB_AUDIT_CASE_SIZE(FUSE_INIT, >=, 8)

        FB_AUDIT_CASE_OUT(FUSE_OPENDIR, fuse_open_out)

        FB_AUDIT_CASE_SIZE(FUSE_READDIR, <=,
            ((struct fuse_read_in *)((char *)ftick->tk_ms_fiov.base +
                                     sizeof(struct fuse_in_header)))->size)

        FB_AUDIT_CASE_NO_OUT(FUSE_RELEASEDIR)

        FB_AUDIT_CASE_NO_OUT(FUSE_FSYNCDIR)

        case FUSE_GETLK:
            panic("osxfuse: no response body format check for FUSE_GETLK");
            break;

        case FUSE_SETLK:
            panic("osxfuse: no response body format check for FUSE_SETLK");
            break;

        case FUSE_SETLKW:
            panic("osxfuse: no response body format check for FUSE_SETLKW");
            break;

        FB_AUDIT_CASE_NO_OUT(FUSE_ACCESS)

        FB_AUDIT_CASE_SIZE(FUSE_CREATE, ==,
                        fuse_entry_out_sizeof(DATOI(data)) +
                        fuse_open_out_sizeof(DATOI(data)))

        case FUSE_INTERRUPT:
            /* TBD */
            break;

        case FUSE_BMAP:
            /* TBD */
            break;

        FB_AUDIT_CASE_NO_OUT(FUSE_DESTROY)

        FB_AUDIT_CASE_SIZE(FUSE_IOCTL, >=,
                        fuse_ioctl_out_sizeof(DATOI(data)))

        case FUSE_POLL:
            /* TBD */
            break;

        case FUSE_NOTIFY_REPLY:
            /* TBD */
            break;

        case FUSE_BATCH_FORGET:
            /* TBD */
            break;

        FB_AUDIT_CASE_NO_OUT(FUSE_FALLOCATE)

        FB_AUDIT_CASE_NO_OUT(FUSE_SETVOLNAME)

        FB_AUDIT_CASE_OUT(FUSE_GETXTIMES, fuse_getxtimes_out)

        FB_AUDIT_CASE_NO_OUT(FUSE_EXCHANGE);

        default:
            IOLog("osxfuse: opcodes out of sync (%d)\n", opcode);
            panic("osxfuse: opcodes out of sync (%d)", opcode);
    }

    return err;

#undef FB_AUDIT_CASE_SIZE
#undef FB_AUDIT_CASE_OUT
#undef FB_AUDIT_CASE_NO_OUT
}

static void
fuse_setup_ihead(struct fuse_in_header *ihead,
                 struct fuse_ticket    *ftick,
                 uint64_t               nid,
                 enum fuse_opcode       op,
                 size_t                 blen,
                 vfs_context_t          context)
{
    ihead->len = (uint32_t)(sizeof(*ihead) + blen);
    ihead->unique = ftick->tk_unique;
    ihead->nodeid = nid;
    ihead->opcode = op;

    if (context) {
        ihead->pid = vfs_context_pid(context);
        ihead->uid = kauth_cred_getuid(vfs_context_ucred(context));
        ihead->gid = kauth_cred_getgid(vfs_context_ucred(context));
    } else {
        /* XXX: could use more thought */
        ihead->pid = proc_selfpid();
        ihead->uid = kauth_getuid();
        ihead->gid = kauth_getgid();
    }
}

static int
fuse_standard_handler(struct fuse_ticket *ftick, uio_t uio)
{
    int err = 0;

    fuse_lck_mtx_lock(ftick->tk_mtx);

    if (ftick->tk_interrupt) {
        struct fuse_ticket *interrupt = ftick->tk_interrupt;

        fuse_internal_interrupt_remove(interrupt);

        /* Release interrupt ticket retained in fuse_internal_interrupt_send */
        ftick->tk_interrupt = NULL;
        fuse_ticket_release(interrupt);
    }

    if (!fticket_answered(ftick)) {
        fticket_set_answered(ftick);

        err = fticket_pull(ftick, uio);
        ftick->tk_aw_errno = err;

        fuse_wakeup(ftick);
    }

    fuse_lck_mtx_unlock(ftick->tk_mtx);

    return err;
}

void
fdisp_make(struct fuse_dispatcher *fdip,
           enum fuse_opcode        op,
           mount_t                 mp,
           uint64_t                nid,
           vfs_context_t           context)
{
    struct fuse_data *data = fuse_get_mpdata(mp);

    if (fdip->tick) {
        fticket_refresh(fdip->tick);
    } else {
        fdip->tick = fuse_ticket_fetch(data);
    }

#ifdef FUSE_TRACE_TICKET
    if (fdip->tick->tk_age == 1) {
        int aw_count = 0;
        int ms_count = 0;

        struct fuse_ticket    *ftick;
        struct fuse_ticket    *x_ftick;

        fuse_lck_mtx_lock(data->ms_mtx);
        STAILQ_FOREACH_SAFE(ftick, &data->ms_head, tk_ms_link, x_ftick) {
            ms_count++;
        }
        fuse_lck_mtx_unlock(data->ms_mtx);

        fuse_lck_mtx_lock(data->aw_mtx);
        TAILQ_FOREACH_SAFE(ftick, &data->aw_head, tk_aw_link, x_ftick) {
            aw_count++;
        }
        fuse_lck_mtx_unlock(data->aw_mtx);

        IOLog("osxfuse: new ticket created op=%d ms_count=%d aw_count=%d\n",
              op, ms_count, aw_count);
    }
#endif

    FUSE_DIMALLOC(&fdip->tick->tk_ms_fiov, fdip->finh,
                  fdip->indata, fdip->iosize);

    fuse_setup_ihead(fdip->finh, fdip->tick, nid, op, fdip->iosize, context);
}

int
fdisp_make_canfail(struct fuse_dispatcher *fdip,
                   enum fuse_opcode        op,
                   mount_t                 mp,
                   uint64_t                nid,
                   vfs_context_t           context)
{
    int failed = 0;
    struct fuse_iov *fiov = NULL;

    struct fuse_data *data = fuse_get_mpdata(mp);

    if (fdip->tick) {
        fticket_refresh(fdip->tick);
    } else {
        fdip->tick = fuse_ticket_fetch(data);
    }

    fiov = &fdip->tick->tk_ms_fiov;

    failed = fiov_adjust_canfail(fiov,
                                 sizeof(struct fuse_in_header) + fdip->iosize);

    if (failed) {
        fuse_ticket_kill(fdip->tick);
        fuse_ticket_release(fdip->tick);
        fdip->tick = NULL;
        return failed;
    }

    fdip->finh = fiov->base;
    fdip->indata = (char *)(fiov->base) + sizeof(struct fuse_in_header);

    fuse_setup_ihead(fdip->finh, fdip->tick, nid, op, fdip->iosize, context);

    return 0;
}

void
fdisp_make_vp(struct fuse_dispatcher *fdip,
              enum fuse_opcode        op,
              vnode_t                 vp,
              vfs_context_t           context)
{
    return fdisp_make(fdip, op, vnode_mount(vp), VTOI(vp), context);
}

int
fdisp_make_vp_canfail(struct fuse_dispatcher *fdip,
                      enum fuse_opcode        op,
                      vnode_t                 vp,
                      vfs_context_t           context)
{
    return fdisp_make_canfail(fdip, op, vnode_mount(vp), VTOI(vp), context);
}

/* The function returns 0 in case of success and errorcode in case of error */
int
fdisp_wait_answ(struct fuse_dispatcher *fdip)
{
    int err = 0;

    fdip->answ_stat = 0;
    fuse_insert_callback(fdip->tick, &fuse_standard_handler);
    fuse_insert_message(fdip->tick);

    err = fticket_wait_answer(fdip->tick);
    if (err) {
        goto out;
    }

    if (fdip->tick->tk_aw_errno) {
        /* Explicitly EIO-ing */

        err = EIO;
        goto out;
    }

    err = fdip->tick->tk_aw_ohead.error;
    if (err) {
        /* Explicitly setting status */

        fdip->answ_stat = err;
        goto out;
    }

    fdip->answ = fticket_resp(fdip->tick)->base;
    fdip->iosize = fticket_resp(fdip->tick)->len;

    return 0;

out:
    fuse_ticket_release(fdip->tick);

    /* We must not reuse this ticket. */
    fdip->tick = NULL;

    return err;
}

#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK

static int
fuse_ipc_notify_audit(struct fuse_data *data, int notify, size_t notify_len) {
#define FN_AUDIT_CASE_SIZE(OPCODE, CMP, SIZE)       \
    case OPCODE:                                    \
        err = (notify_len CMP (SIZE)) ? 0 : EINVAL; \
        break;

#define FN_AUDIT_CASE_OUT(OPCODE, NAME) \
    FN_AUDIT_CASE_SIZE(OPCODE, ==, NAME ## _sizeof(DATOI(data)))

#define FN_AUDIT_CASE_NO_OUT(OPCODE) FN_AUDIT_CASE_SIZE(OPCODE, ==, 0)

    int err = 0;

    if (!fuse_abi_is_notify_supported(DTOABI(data), notify)) {
        return EINVAL;
    }

    switch (notify) {
        FN_AUDIT_CASE_OUT(FUSE_NOTIFY_POLL, fuse_notify_poll_wakeup_out)

        FN_AUDIT_CASE_OUT(FUSE_NOTIFY_INVAL_INODE, fuse_notify_inval_inode_out)

        FN_AUDIT_CASE_SIZE(FUSE_NOTIFY_INVAL_ENTRY, >=,
                           fuse_notify_inval_entry_out_sizeof(DATOI(data)))

        FN_AUDIT_CASE_OUT(FUSE_NOTIFY_STORE, fuse_notify_store_out)

        FN_AUDIT_CASE_OUT(FUSE_NOTIFY_RETRIEVE, fuse_notify_retrieve_out)

        FN_AUDIT_CASE_SIZE(FUSE_NOTIFY_DELETE, >=,
                           fuse_notify_delete_out_sizeof(DATOI(data)))

        default:
            panic("osxfuse: notification codes out of sync (%d)", notify);
    }

    return err;

#undef FN_AUDIT_CASE_SIZE
#undef FN_AUDIT_CASE_OUT
#undef FN_AUDIT_CASE_NO_OUT
}

#endif /* M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */

int
fuse_ipc_notify_handler(struct fuse_data *data, int notify, uio_t uio) {
#if M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK
    int err = 0;

    struct fuse_iov iov;

    if (fdata_dead_get(data)) {
        /* Ignore notification */
        return 0;
    }

    err = fuse_ipc_notify_audit(data, notify, (size_t)uio_resid(uio));
    if (err) {
        return err;
    }

    fiov_init(&iov, (size_t)uio_resid(uio));
    err = uiomove(iov.base, (int)uio_resid(uio), uio);
    if (err) {
        goto out;
    }

    switch (notify) {
        case FUSE_NOTIFY_POLL:
            /* Not implemented */
            break;

        case FUSE_NOTIFY_INVAL_ENTRY:
            err = fuse_notify_inval_entry(data, &iov);
            break;

        case FUSE_NOTIFY_INVAL_INODE:
            err = fuse_notify_inval_inode(data, &iov);
            break;

        case FUSE_NOTIFY_DELETE:
            err = fuse_notify_delete(data, &iov);
            break;

        case FUSE_NOTIFY_STORE:
        case FUSE_NOTIFY_RETRIEVE:
            /* Not implemented */
            break;
    }

out:
    fiov_teardown(&iov);
    return err;
#else /* !M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */
    /*
     * Unsolicited notifications require node locks. Because notifications are
     * sent through the osxfuse device there is no kernel provided node locking
     * mechanism to use as a fallback. Ignore notification.
     */
    (void)data;
    (void)notify;
    (void)uio;
    return 0;
#endif /* M_OSXFUSE_ENABLE_INTERIM_FSNODE_LOCK */
}
