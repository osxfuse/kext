/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <kern/thread.h>
#include <kern/locks.h>
#include <mach/kern_return.h>

#include "fuse.h"
#include "fuse_device.h"
#include "fuse_sysctl.h"
#include <fuse_param.h>
#include <fuse_version.h>

lck_grp_t *osxfuse_lock_group  = NULL;
lck_rw_t  *osxfuse_sysctl_lock = NULL;

static thread_t osxfuse_sysctl_macfuse_thread;
static void osxfuse_thread_macfuse_mode(void *, wait_result_t);

/* NB: none of these are bigger than unsigned 32-bit. */

int32_t  fuse_admin_group            = 0;                                  // rw
int32_t  fuse_allow_other            = 0;                                  // rw
uint32_t fuse_api_major              = FUSE_KERNEL_VERSION;                // r
uint32_t fuse_api_minor              = FUSE_KERNEL_MINOR_VERSION;          // r
int32_t  fuse_fh_current             = 0;                                  // r
uint32_t fuse_fh_reuse_count         = 0;                                  // r
uint32_t fuse_fh_upcall_count        = 0;                                  // r
uint32_t fuse_fh_zombies             = 0;                                  // r
int32_t  fuse_iov_credit             = FUSE_DEFAULT_IOV_CREDIT;            // rw
int32_t  fuse_iov_current            = 0;                                  // r
uint32_t fuse_iov_permanent_bufsize  = FUSE_DEFAULT_IOV_PERMANENT_BUFSIZE; // rw
int32_t  fuse_kill                   = -1;                                 // w
int32_t  fuse_print_vnodes           = -1;                                 // w
int32_t  fuse_macfuse_mode           = 0;                                  // rw
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

SYSCTL_DECL(_osxfuse);
SYSCTL_NODE(, OID_AUTO, osxfuse, CTLFLAG_RW, 0,
            "OSXFUSE Sysctl Interface");
SYSCTL_NODE(_osxfuse, OID_AUTO, control, CTLFLAG_RW, 0,
            "OSXFUSE Controls");
SYSCTL_NODE(_osxfuse, OID_AUTO, counters, CTLFLAG_RW, 0,
            "OSXFUSE Monotonic Counters");
SYSCTL_NODE(_osxfuse, OID_AUTO, resourceusage, CTLFLAG_RW, 0,
            "OSXFUSE Resource Usage");
SYSCTL_NODE(_osxfuse, OID_AUTO, tunables, CTLFLAG_RW, 0,
            "OSXFUSE Tunables");
SYSCTL_NODE(_osxfuse, OID_AUTO, version, CTLFLAG_RW, 0,
            "OSXFUSE Version Information");

SYSCTL_DECL(_macfuse);
SYSCTL_NODE(, OID_AUTO, macfuse, CTLFLAG_RW, 0,
            "MacFUSE Sysctl Interface");
SYSCTL_NODE(_macfuse, OID_AUTO, control, CTLFLAG_RW, 0,
            "MacFUSE Controls");
SYSCTL_NODE(_macfuse, OID_AUTO, counters, CTLFLAG_RW, 0,
            "MacFUSE Monotonic Counters");
SYSCTL_NODE(_macfuse, OID_AUTO, resourceusage, CTLFLAG_RW, 0,
            "MacFUSE Resource Usage");
SYSCTL_NODE(_macfuse, OID_AUTO, tunables, CTLFLAG_RW, 0,
            "MacFUSE Tunables");
SYSCTL_NODE(_macfuse, OID_AUTO, version, CTLFLAG_RW, 0,
            "MacFUSE Version Information");

/* fuse.control */

int sysctl_osxfuse_control_kill_handler SYSCTL_HANDLER_ARGS;
int sysctl_osxfuse_control_print_vnodes_handler SYSCTL_HANDLER_ARGS;
int sysctl_osxfuse_control_macfuse_mode_handler SYSCTL_HANDLER_ARGS;
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
        error = SYSCTL_IN(req, arg1, sizeof(int));
        if (error == 0) {
            int val = *(int *)arg1;
            if (val) {
                fuse_macfuse_mode = 1;
            } else {
                fuse_macfuse_mode = 0;
            }
            
            lck_rw_lock_exclusive(osxfuse_sysctl_lock);
            
            kern_return_t kr;
            kr = kernel_thread_start(osxfuse_thread_macfuse_mode, &fuse_macfuse_mode, &osxfuse_sysctl_macfuse_thread);
            if (kr != KERN_SUCCESS) {
                IOLog("OSXFUSE: could not change status of MacFUSE mode\n");
            }
        }
    }
    
    return error;
}

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

SYSCTL_PROC(_osxfuse_control, // our parent
            OID_AUTO,         // automatically assign object ID
            kill,             // our name

            // type flag/access flag
            (CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_ANYBODY),

            &fuse_kill,       // location of our data
            0,                // argument passed to our handler

            // our handler function
            sysctl_osxfuse_control_kill_handler,

            "I",              // our data type (integer)
            "OSXFUSE Controls: Kill the Given File System");

SYSCTL_PROC(_osxfuse_control,   // our parent
            OID_AUTO,           // automatically assign object ID
            print_vnodes,       // our name

            // type flag/access flag
            (CTLTYPE_INT | CTLFLAG_WR),

            &fuse_print_vnodes, // location of our data
            0,                  // argument passed to our handler

            // our handler function
            sysctl_osxfuse_control_print_vnodes_handler,

            "I",                // our data type (integer)
            "OSXFUSE Controls: Print Vnodes for the Given File System");

SYSCTL_PROC(_osxfuse_control,   // our parent
            OID_AUTO,           // automatically assign object ID
            macfuse_mode,       // our name
            
            // type flag/access flag
            (CTLTYPE_INT | CTLFLAG_RW),
            
            &fuse_macfuse_mode, // location of our data
            0,                  // argument passed to our handler
            
            // our handler function
            sysctl_osxfuse_control_macfuse_mode_handler,
            
            "I",                // our data type (integer)
            "OSXFUSE Controls: Enable/Disable MacFUSE compatibility mode");

SYSCTL_PROC(_macfuse_control, // our parent
            OID_AUTO,         // automatically assign object ID
            kill,             // our name
            
            // type flag/access flag
            (CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_ANYBODY | CTLFLAG_LOCKED),
            
            &fuse_kill,       // location of our data
            0,                // argument passed to our handler
            
            // our handler function
            sysctl_osxfuse_control_kill_handler,
            
            "I",              // our data type (integer)
            "MacFUSE Controls: Kill the Given File System");

SYSCTL_PROC(_macfuse_control,   // our parent
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

/* fuse.counters */
SYSCTL_INT(_osxfuse_counters, OID_AUTO, filehandle_reuse, CTLFLAG_RD,
           &fuse_fh_reuse_count, 0, "");
SYSCTL_INT(_osxfuse_counters, OID_AUTO, filehandle_upcalls, CTLFLAG_RD,
           &fuse_fh_upcall_count, 0, "");
SYSCTL_INT(_osxfuse_counters, OID_AUTO, lookup_cache_hits, CTLFLAG_RD,
           &fuse_lookup_cache_hits, 0, "");
SYSCTL_INT(_osxfuse_counters, OID_AUTO, lookup_cache_misses, CTLFLAG_RD,
           &fuse_lookup_cache_misses, 0, "");
SYSCTL_INT(_osxfuse_counters, OID_AUTO, lookup_cache_overrides,
           CTLFLAG_RD, &fuse_lookup_cache_overrides, 0, "");
SYSCTL_INT(_osxfuse_counters, OID_AUTO, memory_reallocs, CTLFLAG_RD,
           &fuse_realloc_count, 0, "");

SYSCTL_INT(_macfuse_counters, OID_AUTO, filehandle_reuse, CTLFLAG_RD,
           &fuse_fh_reuse_count, 0, "");
SYSCTL_INT(_macfuse_counters, OID_AUTO, filehandle_upcalls, CTLFLAG_RD,
           &fuse_fh_upcall_count, 0, "");
SYSCTL_INT(_macfuse_counters, OID_AUTO, lookup_cache_hits, CTLFLAG_RD,
           &fuse_lookup_cache_hits, 0, "");
SYSCTL_INT(_macfuse_counters, OID_AUTO, lookup_cache_misses, CTLFLAG_RD,
           &fuse_lookup_cache_misses, 0, "");
SYSCTL_INT(_macfuse_counters, OID_AUTO, lookup_cache_overrides,
           CTLFLAG_RD, &fuse_lookup_cache_overrides, 0, "");
SYSCTL_INT(_macfuse_counters, OID_AUTO, memory_reallocs, CTLFLAG_RD,
           &fuse_realloc_count, 0, "");

/* fuse.resourceusage */
SYSCTL_INT(_osxfuse_resourceusage, OID_AUTO, filehandles, CTLFLAG_RD,
           &fuse_fh_current, 0, "");
SYSCTL_INT(_osxfuse_resourceusage, OID_AUTO, filehandles_zombies, CTLFLAG_RD,
           &fuse_fh_zombies, 0, "");
SYSCTL_INT(_osxfuse_resourceusage, OID_AUTO, ipc_iovs, CTLFLAG_RD,
           &fuse_iov_current, 0, "");
SYSCTL_INT(_osxfuse_resourceusage, OID_AUTO, ipc_tickets, CTLFLAG_RD,
           &fuse_tickets_current, 0, "");
SYSCTL_INT(_osxfuse_resourceusage, OID_AUTO, memory_bytes, CTLFLAG_RD,
           &fuse_memory_allocated, 0, "");
SYSCTL_INT(_osxfuse_resourceusage, OID_AUTO, mounts, CTLFLAG_RD,
           &fuse_mount_count, 0, "");
SYSCTL_INT(_osxfuse_resourceusage, OID_AUTO, vnodes, CTLFLAG_RD,
           &fuse_vnodes_current, 0, "");

SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, filehandles, CTLFLAG_RD,
           &fuse_fh_current, 0, "");
SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, filehandles_zombies, CTLFLAG_RD,
           &fuse_fh_zombies, 0, "");
SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, ipc_iovs, CTLFLAG_RD,
           &fuse_iov_current, 0, "");
SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, ipc_tickets, CTLFLAG_RD,
           &fuse_tickets_current, 0, "");
SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, memory_bytes, CTLFLAG_RD,
           &fuse_memory_allocated, 0, "");
SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, mounts, CTLFLAG_RD,
           &fuse_mount_count, 0, "");
SYSCTL_INT(_macfuse_resourceusage, OID_AUTO, vnodes, CTLFLAG_RD,
           &fuse_vnodes_current, 0, "");


/* fuse.tunables */
SYSCTL_INT(_osxfuse_tunables, OID_AUTO, admin_group, CTLFLAG_RW,
           &fuse_admin_group, 0, "");
SYSCTL_INT(_osxfuse_tunables, OID_AUTO, allow_other, CTLFLAG_RW,
           &fuse_allow_other, 0, "");
SYSCTL_INT(_osxfuse_tunables, OID_AUTO, iov_credit, CTLFLAG_RW,
           &fuse_iov_credit, 0, "");
SYSCTL_INT(_osxfuse_tunables, OID_AUTO, iov_permanent_bufsize, CTLFLAG_RW,
           &fuse_iov_permanent_bufsize, 0, "");
SYSCTL_INT(_osxfuse_tunables, OID_AUTO, max_freetickets, CTLFLAG_RW,
           &fuse_max_freetickets, 0, "");
SYSCTL_INT(_osxfuse_tunables, OID_AUTO, max_tickets, CTLFLAG_RW,
           &fuse_max_tickets, 0, "");
SYSCTL_PROC(_osxfuse_tunables,          // our parent
            OID_AUTO,                   // automatically assign object ID
            userkernel_bufsize,         // our name
            (CTLTYPE_INT | CTLFLAG_WR), // type flag/access flag
            &fuse_userkernel_bufsize,   // location of our data
            0,                          // argument passed to our handler
            sysctl_osxfuse_tunables_userkernel_bufsize_handler,    
            "I",                        // our data type (integer)
            "OSXFUSE Tunables");        // our description

SYSCTL_INT(_macfuse_tunables, OID_AUTO, admin_group, CTLFLAG_RW,
           &fuse_admin_group, 0, "");
SYSCTL_INT(_macfuse_tunables, OID_AUTO, allow_other, CTLFLAG_RW,
           &fuse_allow_other, 0, "");
SYSCTL_INT(_macfuse_tunables, OID_AUTO, iov_credit, CTLFLAG_RW,
           &fuse_iov_credit, 0, "");
SYSCTL_INT(_macfuse_tunables, OID_AUTO, iov_permanent_bufsize, CTLFLAG_RW,
           &fuse_iov_permanent_bufsize, 0, "");
SYSCTL_INT(_macfuse_tunables, OID_AUTO, max_freetickets, CTLFLAG_RW,
           &fuse_max_freetickets, 0, "");
SYSCTL_INT(_macfuse_tunables, OID_AUTO, max_tickets, CTLFLAG_RW,
           &fuse_max_tickets, 0, "");
SYSCTL_PROC(_macfuse_tunables,          // our parent
            OID_AUTO,                   // automatically assign object ID
            userkernel_bufsize,         // our name
            (CTLTYPE_INT | CTLFLAG_WR), // type flag/access flag
            &fuse_userkernel_bufsize,   // location of our data
            0,                          // argument passed to our handler
            sysctl_osxfuse_tunables_userkernel_bufsize_handler,    
            "I",                        // our data type (integer)
            "MacFUSE Tunables");        // our description

/* fuse.version */
SYSCTL_INT(_osxfuse_version, OID_AUTO, api_major, CTLFLAG_RD,
           &fuse_api_major, 0, "");
SYSCTL_INT(_osxfuse_version, OID_AUTO, api_minor, CTLFLAG_RD,
           &fuse_api_minor, 0, "");
SYSCTL_STRING(_osxfuse_version, OID_AUTO, number, CTLFLAG_RD,
              OSXFUSE_VERSION, 0, "");
SYSCTL_STRING(_osxfuse_version, OID_AUTO, string, CTLFLAG_RD,
              OSXFUSE_VERSION ", " OSXFUSE_TIMESTAMP, 0, "");

SYSCTL_INT(_macfuse_version, OID_AUTO, api_major, CTLFLAG_RD,
           &fuse_api_major, 0, "");
SYSCTL_INT(_macfuse_version, OID_AUTO, api_minor, CTLFLAG_RD,
           &fuse_api_minor, 0, "");
SYSCTL_STRING(_macfuse_version, OID_AUTO, number, CTLFLAG_RD,
              OSXFUSE_VERSION, 0, "");
SYSCTL_STRING(_macfuse_version, OID_AUTO, string, CTLFLAG_RD,
              OSXFUSE_VERSION ", " OSXFUSE_TIMESTAMP, 0, "");

static struct sysctl_oid *fuse_sysctl_list[] =
{
    &sysctl__osxfuse_control,
    &sysctl__osxfuse_counters,
    &sysctl__osxfuse_resourceusage,
    &sysctl__osxfuse_tunables,
    &sysctl__osxfuse_version,
    &sysctl__osxfuse_control_kill,
    &sysctl__osxfuse_control_print_vnodes,
    &sysctl__osxfuse_control_macfuse_mode,
    &sysctl__osxfuse_counters_filehandle_reuse,
    &sysctl__osxfuse_counters_filehandle_upcalls,
    &sysctl__osxfuse_counters_lookup_cache_hits,
    &sysctl__osxfuse_counters_lookup_cache_misses,
    &sysctl__osxfuse_counters_lookup_cache_overrides,
    &sysctl__osxfuse_counters_memory_reallocs,
    &sysctl__osxfuse_resourceusage_filehandles,
    &sysctl__osxfuse_resourceusage_filehandles_zombies,
    &sysctl__osxfuse_resourceusage_ipc_iovs,
    &sysctl__osxfuse_resourceusage_ipc_tickets,
    &sysctl__osxfuse_resourceusage_memory_bytes,
    &sysctl__osxfuse_resourceusage_mounts,
    &sysctl__osxfuse_resourceusage_vnodes,
    &sysctl__osxfuse_tunables_admin_group,
    &sysctl__osxfuse_tunables_allow_other,
    &sysctl__osxfuse_tunables_iov_credit,
    &sysctl__osxfuse_tunables_iov_permanent_bufsize,
    &sysctl__osxfuse_tunables_max_freetickets,
    &sysctl__osxfuse_tunables_max_tickets,
    &sysctl__osxfuse_tunables_userkernel_bufsize,
    &sysctl__osxfuse_version_api_major,
    &sysctl__osxfuse_version_api_minor,
    &sysctl__osxfuse_version_number,
    &sysctl__osxfuse_version_string,
    (struct sysctl_oid *)0
};

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
    &sysctl__macfuse_version_api_major,
    &sysctl__macfuse_version_api_minor,
    &sysctl__macfuse_version_number,
    &sysctl__macfuse_version_string,
    (struct sysctl_oid *)0
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
osxfuse_thread_macfuse_mode(void * parameter, __unused wait_result_t wait_result) {
    int enabled = *((int *) parameter);
    if (enabled) {
        fuse_sysctl_macfuse_start();
    } else {
        fuse_sysctl_macfuse_stop();
    }
    
    lck_rw_unlock_exclusive(osxfuse_sysctl_lock);

    thread_terminate(current_thread());
}

void
fuse_sysctl_start(void)
{        
    osxfuse_lock_group  = lck_grp_alloc_init("osxfuse", NULL);
    osxfuse_sysctl_lock = lck_rw_alloc_init(osxfuse_lock_group, NULL);
    
    int i;

    sysctl_register_oid(&sysctl__osxfuse);
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
    sysctl_unregister_oid(&sysctl__osxfuse);

    lck_rw_lock_exclusive(osxfuse_sysctl_lock);
    
    thread_deallocate(osxfuse_sysctl_macfuse_thread);
    if (fuse_macfuse_mode) {
        fuse_sysctl_macfuse_stop();
    }
    
    lck_rw_unlock_exclusive(osxfuse_sysctl_lock);
    
    lck_rw_free(osxfuse_sysctl_lock, osxfuse_lock_group);
    lck_grp_free(osxfuse_lock_group);
}
