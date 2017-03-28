/*
 * Copyright (c) 2006-2008 Amit Singh/Google Inc.
 * Copyright (c) 2011-2017 Benjamin Fleischer
 * All rights reserved.
 */

#include "fuse_sysctl.h"

#include "fuse_device.h"

#include <fuse_param.h>
#include <fuse_version.h>

#include <sys/sysctl.h>

#if OSXFUSE_ENABLE_MACFUSE_MODE
#include <kern/thread.h>

static lck_grp_t *osxfuse_lock_group  = NULL;
static lck_mtx_t *osxfuse_sysctl_lock = NULL;

static void osxfuse_thread_macfuse_mode(void *, wait_result_t);

#endif /* OSXFUSE_ENABLE_MACFUSE_MODE */

/* NB: none of these are bigger than unsigned 32-bit. */

int32_t  fuse_admin_group            = 0;                                  // rw
int32_t  fuse_allow_other            = FUSE_DEFAULT_ALLOW_OTHER;           // rw
uint32_t fuse_abi_major              = FUSE_KERNEL_VERSION;                // r
uint32_t fuse_abi_minor              = FUSE_KERNEL_MINOR_VERSION;          // r
int32_t  fuse_fh_current             = 0;                                  // r
uint32_t fuse_fh_reuse_count         = 0;                                  // r
uint32_t fuse_fh_upcall_count        = 0;                                  // r
uint32_t fuse_fh_zombies             = 0;                                  // r
int32_t  fuse_iov_credit             = FUSE_DEFAULT_IOV_CREDIT;            // rw
int32_t  fuse_iov_current            = 0;                                  // r
uint32_t fuse_iov_permanent_bufsize  = FUSE_DEFAULT_IOV_PERMANENT_BUFSIZE; // rw
int32_t  fuse_kill                   = -1;                                 // w
int32_t  fuse_print_vnodes           = -1;                                 // w
#if OSXFUSE_ENABLE_MACFUSE_MODE
int32_t  fuse_macfuse_mode           = 0;                                  // rw
#endif
uint32_t fuse_lookup_cache_hits      = 0;                                  // r
uint32_t fuse_lookup_cache_misses    = 0;                                  // r
uint32_t fuse_lookup_cache_overrides = 0;                                  // r
uint32_t fuse_max_freetickets        = FUSE_DEFAULT_MAX_FREE_TICKETS;      // rw
uint32_t fuse_max_tickets            = 0;                                  // rw
int32_t  fuse_mount_count            = 0;                                  // r
int32_t  fuse_memory_allocated       = 0;                                  // r
int32_t  fuse_realloc_count          = 0;                                  // r
int32_t  fuse_tickets_current        = 0;                                  // r
uint32_t fuse_userkernel_bufsize     = FUSE_DEFAULT_USERKERNEL_BUFSIZE;    // rw
int32_t  fuse_vnodes_current         = 0;                                  // r


#define OSXFUSE_SYSCTL_ROOT  FUSE_PP_CAT(_vfs_generic_, OSXFUSE_NAME_LITERAL)
#define OSXFUSE_SYSCTL(name) FUSE_PP_CAT(OSXFUSE_SYSCTL_ROOT, _, name)

#define OSXFUSE_SYSCTL_VAR_ROOT  FUSE_PP_CAT(sysctl_, OSXFUSE_SYSCTL_ROOT)
#define OSXFUSE_SYSCTL_VAR(name) FUSE_PP_CAT(OSXFUSE_SYSCTL_VAR_ROOT, _, name)


/* SYSCTL_* macro wrappers */

#define CALL(macro, ...) macro(__VA_ARGS__)

#define OSXFUSE_SYSCTL_DECL(name) \
    CALL(SYSCTL_DECL, name)

#define OSXFUSE_SYSCTL_NODE(parent, nbr, name, access, handler, descr) \
    CALL(SYSCTL_NODE, parent, nbr, name, access, handler, descr)

#define OSXFUSE_SYSCTL_INT(parent, nbr, name, access, ptr, val, descr) \
    CALL(SYSCTL_INT, parent, nbr, name, access, ptr, val, descr)

#define OSXFUSE_SYSCTL_STRING(parent, nbr, name, access, arg, len, descr) \
    CALL(SYSCTL_STRING, parent, nbr, name, access, arg, len, descr)

#define OSXFUSE_SYSCTL_PROC(parent, nbr, name, access, ptr, arg, handler, fmt, \
                            descr) \
    CALL(SYSCTL_PROC, parent, nbr, name, access, ptr, arg, handler, fmt, descr)


SYSCTL_DECL(_vfs_generic);
OSXFUSE_SYSCTL_NODE(_vfs_generic, OID_AUTO, OSXFUSE_NAME_LITERAL, CTLFLAG_RW, 0,
                    OSXFUSE_DISPLAY_NAME " Sysctl Interface");
OSXFUSE_SYSCTL_NODE(OSXFUSE_SYSCTL_ROOT, OID_AUTO, control, CTLFLAG_RW, 0,
                    OSXFUSE_DISPLAY_NAME " Controls");
OSXFUSE_SYSCTL_NODE(OSXFUSE_SYSCTL_ROOT, OID_AUTO, counters, CTLFLAG_RW, 0,
                    OSXFUSE_DISPLAY_NAME " Monotonic Counters");
OSXFUSE_SYSCTL_NODE(OSXFUSE_SYSCTL_ROOT, OID_AUTO, resourceusage, CTLFLAG_RW, 0,
                    OSXFUSE_DISPLAY_NAME " Resource Usage");
OSXFUSE_SYSCTL_NODE(OSXFUSE_SYSCTL_ROOT, OID_AUTO, tunables, CTLFLAG_RW, 0,
                    OSXFUSE_DISPLAY_NAME " Tunables");
OSXFUSE_SYSCTL_NODE(OSXFUSE_SYSCTL_ROOT, OID_AUTO, version, CTLFLAG_RW, 0,
                    OSXFUSE_DISPLAY_NAME " Version Information");

#if OSXFUSE_ENABLE_MACFUSE_MODE
OSXFUSE_SYSCTL_DECL(_macfuse);
OSXFUSE_SYSCTL_NODE(, OID_AUTO, macfuse, CTLFLAG_RW, 0,
                    "MacFUSE Sysctl Interface");
OSXFUSE_SYSCTL_NODE(_macfuse, OID_AUTO, control, CTLFLAG_RW, 0,
                    "MacFUSE Controls");
OSXFUSE_SYSCTL_NODE(_macfuse, OID_AUTO, counters, CTLFLAG_RW, 0,
                    "MacFUSE Monotonic Counters");
OSXFUSE_SYSCTL_NODE(_macfuse, OID_AUTO, resourceusage, CTLFLAG_RW, 0,
                    "MacFUSE Resource Usage");
OSXFUSE_SYSCTL_NODE(_macfuse, OID_AUTO, tunables, CTLFLAG_RW, 0,
                    "MacFUSE Tunables");
OSXFUSE_SYSCTL_NODE(_macfuse, OID_AUTO, version, CTLFLAG_RW, 0,
                    "MacFUSE Version Information");
#endif

/* fuse.control */

int sysctl_osxfuse_control_kill_handler SYSCTL_HANDLER_ARGS;
int sysctl_osxfuse_control_print_vnodes_handler SYSCTL_HANDLER_ARGS;
#if OSXFUSE_ENABLE_MACFUSE_MODE
int sysctl_osxfuse_control_macfuse_mode_handler SYSCTL_HANDLER_ARGS;
#endif
int sysctl_osxfuse_tunables_userkernel_bufsize_handler SYSCTL_HANDLER_ARGS;

int
sysctl_osxfuse_control_kill_handler SYSCTL_HANDLER_ARGS
{
    int error = 0;
    (void)oidp;

    if (arg1) {
        error = SYSCTL_OUT(req, arg1, sizeof(int));
    } else {
        error = SYSCTL_OUT(req, &arg2, sizeof(int));
    }

    if (error || !req->newptr) {
        return error;
    }

    if (!arg1) {
        error = EPERM;
    } else {
        error = SYSCTL_IN(req, arg1, sizeof(int));
        if (error == 0) {
            error = fuse_device_kill(*(int *)arg1, req->p);
        }
        fuse_kill = -1; /* set it back */
    }

    return error;
}

int
sysctl_osxfuse_control_print_vnodes_handler SYSCTL_HANDLER_ARGS
{
    int error = 0;
    (void)oidp;

    if (arg1) {
        error = SYSCTL_OUT(req, arg1, sizeof(uint32_t));
    } else {
        error = SYSCTL_OUT(req, &arg2, sizeof(uint32_t));
    }

    if (error || !req->newptr) {
        return error;
    }

    if (!arg1) {
        error = EPERM;
    } else {
        error = SYSCTL_IN(req, arg1, sizeof(int));
        if (error == 0) {
            error = fuse_device_print_vnodes(*(int *)arg1, req->p);
        }
        fuse_print_vnodes = -1; /* set it back */
    }

    return error;
}

#if OSXFUSE_ENABLE_MACFUSE_MODE

int
sysctl_osxfuse_control_macfuse_mode_handler SYSCTL_HANDLER_ARGS
{
    int error = 0;
    (void)oidp;

    if (arg1) {
        error = SYSCTL_OUT(req, arg1, sizeof(uint32_t));
    } else {
        error = SYSCTL_OUT(req, &arg2, sizeof(uint32_t));
    }

    if (error || !req->newptr) {
        return error;
    }

    if (!arg1) {
        error = EPERM;
    } else {
        int val;
        error = SYSCTL_IN(req, &val, sizeof(int));
        if (error == 0) {
            if (val) {
                val = 1;
            } else {
                val = 0;
            }

            lck_mtx_lock(osxfuse_sysctl_lock);
            if (fuse_macfuse_mode == val) {
                lck_mtx_unlock(osxfuse_sysctl_lock);
            } else {
                thread_t macfuse_mode_thread;

                fuse_macfuse_mode = val;

                kern_return_t kr;
                kr = kernel_thread_start(osxfuse_thread_macfuse_mode, NULL,
                                         &macfuse_mode_thread);
                if (kr != KERN_SUCCESS) {
                    IOLog("osxfuse: could not change status of MacFUSE mode\n");
                } else {
                    thread_deallocate(macfuse_mode_thread);
                }

                // osxfuse_sysctl_lock is unlocked in osxfuse_thread_macfuse_mode
            }
        }
    }

    return error;
}

#endif /* OSXFUSE_ENABLE_MACFUSE_MODE */

int
sysctl_osxfuse_tunables_userkernel_bufsize_handler SYSCTL_HANDLER_ARGS
{
    int error = 0;
    (void)oidp;

    if (arg1) {
        error = SYSCTL_OUT(req, arg1, sizeof(int));
    } else {
        error = SYSCTL_OUT(req, &arg2, sizeof(int));
    }

    if (error || !req->newptr) {
        return error;
    }

    if (!arg1) {
        error = EPERM;
    } else {
        error = SYSCTL_IN(req, arg1, sizeof(uint32_t));
        if (error == 0) {
            uint32_t incoming = *(uint32_t *)arg1;
            incoming = fuse_round_page_32(incoming);
            if (incoming > FUSE_MAX_USERKERNEL_BUFSIZE) {
                error = E2BIG;
            } else if (incoming < FUSE_MIN_USERKERNEL_BUFSIZE) {
                error = EINVAL;
            } else {
                fuse_userkernel_bufsize = incoming;
            }
        }
    }

    return error;
}

OSXFUSE_SYSCTL_PROC(OSXFUSE_SYSCTL(control), // our parent
                    OID_AUTO,                // automatically assign object ID
                    kill,                    // our name

                    // type flag/access flag
                    (CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_ANYBODY),

                    &fuse_kill,       // location of our data
                    0,                // argument passed to our handler

                    // our handler function
                    sysctl_osxfuse_control_kill_handler,

                    "I",              // our data type (integer)
                    OSXFUSE_DISPLAY_NAME " Controls: Kill the Given File "
                    "System");

OSXFUSE_SYSCTL_PROC(OSXFUSE_SYSCTL(control), // our parent
                    OID_AUTO,                // automatically assign object ID
                    print_vnodes,            // our name

                    // type flag/access flag
                    (CTLTYPE_INT | CTLFLAG_WR),

                    &fuse_print_vnodes, // location of our data
                    0,                  // argument passed to our handler

                    // our handler function
                    sysctl_osxfuse_control_print_vnodes_handler,

                    "I",                // our data type (integer)
                    OSXFUSE_DISPLAY_NAME " Controls: Print Vnodes for the Given "
                    "File System");

#if OSXFUSE_ENABLE_MACFUSE_MODE

OSXFUSE_SYSCTL_PROC(OSXFUSE_SYSCTL(control), // our parent
                    OID_AUTO,                // automatically assign object ID
                    macfuse_mode,            // our name

                    // type flag/access flag
                    (CTLTYPE_INT | CTLFLAG_RW),

                    &fuse_macfuse_mode, // location of our data
                    0,                  // argument passed to our handler

                    // our handler function
                    sysctl_osxfuse_control_macfuse_mode_handler,

                    "I",                // our data type (integer)
                    OSXFUSE_DISPLAY_NAME " Controls: Enable/Disable MacFUSE "
                    "Compatibility Mode");

OSXFUSE_SYSCTL_PROC(_macfuse_control, // our parent
                    OID_AUTO,         // automatically assign object ID
                    kill,             // our name

                    // type flag/access flag
                    (CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_ANYBODY |
                     CTLFLAG_LOCKED),

                    &fuse_kill,       // location of our data
                    0,                // argument passed to our handler

                    // our handler function
                    sysctl_osxfuse_control_kill_handler,

                    "I",              // our data type (integer)
                    "MacFUSE Controls: Kill the Given File System");

OSXFUSE_SYSCTL_PROC(_macfuse_control,   // our parent
                    OID_AUTO,           // automatically assign object ID
                    print_vnodes,       // our name

                    // type flag/access flag
                    (CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_LOCKED),

                    &fuse_print_vnodes, // location of our data
                    0,                  // argument passed to our handler

                    // our handler function
                    sysctl_osxfuse_control_print_vnodes_handler,

                    "I",                // our data type (integer)
                    "MacFUSE Controls: Print Vnodes for the Given File System");

#endif

/* fuse.counters */
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(counters), OID_AUTO, filehandle_reuse,
                   CTLFLAG_RD, &fuse_fh_reuse_count, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(counters), OID_AUTO, filehandle_upcalls,
                   CTLFLAG_RD, &fuse_fh_upcall_count, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(counters), OID_AUTO, lookup_cache_hits,
                   CTLFLAG_RD, &fuse_lookup_cache_hits, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(counters), OID_AUTO, lookup_cache_misses,
                   CTLFLAG_RD, &fuse_lookup_cache_misses, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(counters), OID_AUTO, lookup_cache_overrides,
                   CTLFLAG_RD, &fuse_lookup_cache_overrides, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(counters), OID_AUTO, memory_reallocs,
                   CTLFLAG_RD, &fuse_realloc_count, 0, "");

#if OSXFUSE_ENABLE_MACFUSE_MODE

OSXFUSE_SYSCTL_INT(_macfuse_counters, OID_AUTO, filehandle_reuse, CTLFLAG_RD,
           &fuse_fh_reuse_count, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_counters, OID_AUTO, filehandle_upcalls, CTLFLAG_RD,
           &fuse_fh_upcall_count, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_counters, OID_AUTO, lookup_cache_hits, CTLFLAG_RD,
           &fuse_lookup_cache_hits, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_counters, OID_AUTO, lookup_cache_misses, CTLFLAG_RD,
           &fuse_lookup_cache_misses, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_counters, OID_AUTO, lookup_cache_overrides,
           CTLFLAG_RD, &fuse_lookup_cache_overrides, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_counters, OID_AUTO, memory_reallocs, CTLFLAG_RD,
           &fuse_realloc_count, 0, "");

#endif

/* fuse.resourceusage */
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(resourceusage), OID_AUTO, filehandles,
                   CTLFLAG_RD, &fuse_fh_current, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(resourceusage), OID_AUTO, filehandles_zombies,
                   CTLFLAG_RD, &fuse_fh_zombies, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(resourceusage), OID_AUTO, ipc_iovs,
                   CTLFLAG_RD, &fuse_iov_current, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(resourceusage), OID_AUTO, ipc_tickets,
                   CTLFLAG_RD, &fuse_tickets_current, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(resourceusage), OID_AUTO, memory_bytes,
                   CTLFLAG_RD, &fuse_memory_allocated, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(resourceusage), OID_AUTO, mounts, CTLFLAG_RD,
                   &fuse_mount_count, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(resourceusage), OID_AUTO, vnodes, CTLFLAG_RD,
                   &fuse_vnodes_current, 0, "");

#if OSXFUSE_ENABLE_MACFUSE_MODE

OSXFUSE_SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, filehandles, CTLFLAG_RD,
                   &fuse_fh_current, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, filehandles_zombies,
                   CTLFLAG_RD, &fuse_fh_zombies, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, ipc_iovs, CTLFLAG_RD,
                   &fuse_iov_current, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, ipc_tickets, CTLFLAG_RD,
                   &fuse_tickets_current, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, memory_bytes, CTLFLAG_RD,
                   &fuse_memory_allocated, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, mounts, CTLFLAG_RD,
                   &fuse_mount_count, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, vnodes, CTLFLAG_RD,
                   &fuse_vnodes_current, 0, "");

#endif

/* fuse.tunables */
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(tunables), OID_AUTO, admin_group, CTLFLAG_RW,
                   &fuse_admin_group, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(tunables), OID_AUTO, allow_other, CTLFLAG_RW,
                   &fuse_allow_other, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(tunables), OID_AUTO, iov_credit, CTLFLAG_RW,
                   &fuse_iov_credit, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(tunables), OID_AUTO, iov_permanent_bufsize,
                   CTLFLAG_RW, &fuse_iov_permanent_bufsize, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(tunables), OID_AUTO, max_freetickets,
                   CTLFLAG_RW, &fuse_max_freetickets, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(tunables), OID_AUTO, max_tickets, CTLFLAG_RW,
                   &fuse_max_tickets, 0, "");
OSXFUSE_SYSCTL_PROC(OSXFUSE_SYSCTL(tunables),   // our parent
                    OID_AUTO,                   // automatically assign object ID
                    userkernel_bufsize,         // our name
                    (CTLTYPE_INT | CTLFLAG_WR), // type flag/access flag
                    &fuse_userkernel_bufsize,   // location of our data
                    0,                          // argument passed to our handler
                    sysctl_osxfuse_tunables_userkernel_bufsize_handler,
                    "I",                        // our data type (integer)
                    OSXFUSE_DISPLAY_NAME " Tunables");

#if OSXFUSE_ENABLE_MACFUSE_MODE

OSXFUSE_SYSCTL_INT(_macfuse_tunables, OID_AUTO, admin_group, CTLFLAG_RW,
                   &fuse_admin_group, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_tunables, OID_AUTO, allow_other, CTLFLAG_RW,
                   &fuse_allow_other, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_tunables, OID_AUTO, iov_credit, CTLFLAG_RW,
                   &fuse_iov_credit, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_tunables, OID_AUTO, iov_permanent_bufsize, CTLFLAG_RW,
                   &fuse_iov_permanent_bufsize, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_tunables, OID_AUTO, max_freetickets, CTLFLAG_RW,
                   &fuse_max_freetickets, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_tunables, OID_AUTO, max_tickets, CTLFLAG_RW,
                   &fuse_max_tickets, 0, "");
OSXFUSE_SYSCTL_PROC(_macfuse_tunables,          // our parent
                    OID_AUTO,                   // automatically assign object ID
                    userkernel_bufsize,         // our name
                    (CTLTYPE_INT | CTLFLAG_WR), // type flag/access flag
                    &fuse_userkernel_bufsize,   // location of our data
                    0,                          // argument passed to our handler
                    sysctl_osxfuse_tunables_userkernel_bufsize_handler,
                    "I",                        // our data type (integer)
                    "MacFUSE Tunables");

#endif

/* fuse.version */
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(version), OID_AUTO, abi_major, CTLFLAG_RD,
                   &fuse_abi_major, 0, "");
OSXFUSE_SYSCTL_INT(OSXFUSE_SYSCTL(version), OID_AUTO, abi_minor, CTLFLAG_RD,
                   &fuse_abi_minor, 0, "");
OSXFUSE_SYSCTL_STRING(OSXFUSE_SYSCTL(version), OID_AUTO, number, CTLFLAG_RD,
                      OSXFUSE_VERSION, 0, "");
OSXFUSE_SYSCTL_STRING(OSXFUSE_SYSCTL(version), OID_AUTO, string, CTLFLAG_RD,
                      OSXFUSE_VERSION ", " OSXFUSE_TIMESTAMP, 0, "");

#if OSXFUSE_ENABLE_MACFUSE_MODE

OSXFUSE_SYSCTL_INT(_macfuse_version, OID_AUTO, abi_major, CTLFLAG_RD,
                   &fuse_abi_major, 0, "");
OSXFUSE_SYSCTL_INT(_macfuse_version, OID_AUTO, abi_minor, CTLFLAG_RD,
                   &fuse_abi_minor, 0, "");
OSXFUSE_SYSCTL_STRING(_macfuse_version, OID_AUTO, number, CTLFLAG_RD,
                      OSXFUSE_VERSION, 0, "");
OSXFUSE_SYSCTL_STRING(_macfuse_version, OID_AUTO, string, CTLFLAG_RD,
                      OSXFUSE_VERSION ", " OSXFUSE_TIMESTAMP, 0, "");

#endif

static struct sysctl_oid *fuse_sysctl_list[] =
{
    &OSXFUSE_SYSCTL_VAR(control),
    &OSXFUSE_SYSCTL_VAR(counters),
    &OSXFUSE_SYSCTL_VAR(resourceusage),
    &OSXFUSE_SYSCTL_VAR(tunables),
    &OSXFUSE_SYSCTL_VAR(version),
    &OSXFUSE_SYSCTL_VAR(control_kill),
    &OSXFUSE_SYSCTL_VAR(control_print_vnodes),
#if OSXFUSE_ENABLE_MACFUSE_MODE
    &OSXFUSE_SYSCTL_VAR(control_macfuse_mode),
#endif
    &OSXFUSE_SYSCTL_VAR(counters_filehandle_reuse),
    &OSXFUSE_SYSCTL_VAR(counters_filehandle_upcalls),
    &OSXFUSE_SYSCTL_VAR(counters_lookup_cache_hits),
    &OSXFUSE_SYSCTL_VAR(counters_lookup_cache_misses),
    &OSXFUSE_SYSCTL_VAR(counters_lookup_cache_overrides),
    &OSXFUSE_SYSCTL_VAR(counters_memory_reallocs),
    &OSXFUSE_SYSCTL_VAR(resourceusage_filehandles),
    &OSXFUSE_SYSCTL_VAR(resourceusage_filehandles_zombies),
    &OSXFUSE_SYSCTL_VAR(resourceusage_ipc_iovs),
    &OSXFUSE_SYSCTL_VAR(resourceusage_ipc_tickets),
    &OSXFUSE_SYSCTL_VAR(resourceusage_memory_bytes),
    &OSXFUSE_SYSCTL_VAR(resourceusage_mounts),
    &OSXFUSE_SYSCTL_VAR(resourceusage_vnodes),
    &OSXFUSE_SYSCTL_VAR(tunables_admin_group),
    &OSXFUSE_SYSCTL_VAR(tunables_allow_other),
    &OSXFUSE_SYSCTL_VAR(tunables_iov_credit),
    &OSXFUSE_SYSCTL_VAR(tunables_iov_permanent_bufsize),
    &OSXFUSE_SYSCTL_VAR(tunables_max_freetickets),
    &OSXFUSE_SYSCTL_VAR(tunables_max_tickets),
    &OSXFUSE_SYSCTL_VAR(tunables_userkernel_bufsize),
    &OSXFUSE_SYSCTL_VAR(version_abi_major),
    &OSXFUSE_SYSCTL_VAR(version_abi_minor),
    &OSXFUSE_SYSCTL_VAR(version_number),
    &OSXFUSE_SYSCTL_VAR(version_string),
    NULL
};

#if OSXFUSE_ENABLE_MACFUSE_MODE

static struct sysctl_oid *fuse_sysctl_list_macfuse[] =
{
    &sysctl__macfuse_control,
    &sysctl__macfuse_counters,
    &sysctl__macfuse_resourceusage,
    &sysctl__macfuse_tunables,
    &sysctl__macfuse_version,
    &sysctl__macfuse_control_kill,
    &sysctl__macfuse_control_print_vnodes,
    &sysctl__macfuse_counters_filehandle_reuse,
    &sysctl__macfuse_counters_filehandle_upcalls,
    &sysctl__macfuse_counters_lookup_cache_hits,
    &sysctl__macfuse_counters_lookup_cache_misses,
    &sysctl__macfuse_counters_lookup_cache_overrides,
    &sysctl__macfuse_counters_memory_reallocs,
    &sysctl__macfuse_resourceusage_filehandles,
    &sysctl__macfuse_resourceusage_filehandles_zombies,
    &sysctl__macfuse_resourceusage_ipc_iovs,
    &sysctl__macfuse_resourceusage_ipc_tickets,
    &sysctl__macfuse_resourceusage_memory_bytes,
    &sysctl__macfuse_resourceusage_mounts,
    &sysctl__macfuse_resourceusage_vnodes,
    &sysctl__macfuse_tunables_admin_group,
    &sysctl__macfuse_tunables_allow_other,
    &sysctl__macfuse_tunables_iov_credit,
    &sysctl__macfuse_tunables_iov_permanent_bufsize,
    &sysctl__macfuse_tunables_max_freetickets,
    &sysctl__macfuse_tunables_max_tickets,
    &sysctl__macfuse_tunables_userkernel_bufsize,
    &sysctl__macfuse_version_abi_major,
    &sysctl__macfuse_version_abi_minor,
    &sysctl__macfuse_version_number,
    &sysctl__macfuse_version_string,
    NULL
};

static void
fuse_sysctl_macfuse_start(void)
{
    int i;

    sysctl_register_oid(&sysctl__macfuse);
    for (i = 0; fuse_sysctl_list_macfuse[i]; i++) {
        sysctl_register_oid(fuse_sysctl_list_macfuse[i]);
    }
}

static void
fuse_sysctl_macfuse_stop(void)
{
    int i;

    for (i = 0; fuse_sysctl_list_macfuse[i]; i++) {
        sysctl_unregister_oid(fuse_sysctl_list_macfuse[i]);
    }
    sysctl_unregister_oid(&sysctl__macfuse);
}

static void
osxfuse_thread_macfuse_mode(__unused void *parameter, __unused wait_result_t wait_result)
{
    if (fuse_macfuse_mode) {
        fuse_sysctl_macfuse_start();
    } else {
        fuse_sysctl_macfuse_stop();
    }

    lck_mtx_unlock(osxfuse_sysctl_lock);
    thread_terminate(current_thread());
}

#endif /* OSXFUSE_ENABLE_MACFUSE_MODE */

void
fuse_sysctl_start(void)
{
    int i;
#if OSXFUSE_ENABLE_MACFUSE_MODE
    osxfuse_lock_group  = lck_grp_alloc_init("osxfuse", NULL);
    osxfuse_sysctl_lock = lck_mtx_alloc_init(osxfuse_lock_group, NULL);
#endif

    sysctl_register_oid(&OSXFUSE_SYSCTL_VAR_ROOT);
    for (i = 0; fuse_sysctl_list[i]; i++) {
       sysctl_register_oid(fuse_sysctl_list[i]);
    }
}

void
fuse_sysctl_stop(void)
{
    int i;

    for (i = 0; fuse_sysctl_list[i]; i++) {
       sysctl_unregister_oid(fuse_sysctl_list[i]);
    }
    sysctl_unregister_oid(&OSXFUSE_SYSCTL_VAR_ROOT);

#if OSXFUSE_ENABLE_MACFUSE_MODE
    lck_mtx_lock(osxfuse_sysctl_lock);

    if (fuse_macfuse_mode) {
        fuse_sysctl_macfuse_stop();
    }

    lck_mtx_unlock(osxfuse_sysctl_lock);

    lck_mtx_free(osxfuse_sysctl_lock, osxfuse_lock_group);
    lck_grp_free(osxfuse_lock_group);
#endif /* OSXFUSE_ENABLE_MACFUSE_MODE */
}
