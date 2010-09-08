/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

/*
 * 'rebel' branch modifications:
 *     Copyright (C) Tuxera 2010. All Rights Reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <mach/mach_types.h>
#include <miscfs/devfs/devfs.h>

#include <libkern/libkern.h>
#include <libkern/OSMalloc.h>
#include <libkern/locks.h>

#include "fuse.h"
#include "fuse_device.h"
#include "fuse_ipc.h"
#include "fuse_locking.h"
#include "fuse_node.h"
#include "fuse_nodehash.h"
#include "fuse_sysctl.h"
#include <fuse_mount.h>

OSMallocTag  fuse_malloc_tag = NULL;

extern struct vfs_fsentry fuse_vfs_entry;
extern vfstable_t         fuse_vfs_table_ref;

kern_return_t fusefs_start(kmod_info_t *ki, void *d);
kern_return_t fusefs_stop(kmod_info_t *ki, void *d);

static void
fini_stuff(void)
{
    if (fuse_device_mutex) {
        lck_mtx_free(fuse_device_mutex, fuse_lock_group);
        fuse_device_mutex = NULL;
    }

#if M_MACFUSE_ENABLE_INTERIM_FSNODE_LOCK
#if M_MACFUSE_ENABLE_HUGE_LOCK
    if (fuse_huge_lock) {
        fusefs_recursive_lock_free(fuse_huge_lock);
        fuse_huge_lock = NULL;
    }
#endif /* M_MACFUSE_ENABLE_HUGE_LOCK */

#if M_MACFUSE_ENABLE_LOCK_LOGGING
    if (fuse_log_lock) {
        lck_mtx_free(fuse_log_lock, fuse_lock_group);
        fuse_log_lock = NULL;
    }
#endif /* M_MACFUSE_ENABLE_LOCK_LOGGING */
#endif /* M_MACFUSE_ENABLE_INTERIM_FSNODE_LOCK */

    if (fuse_lock_group) {
        lck_grp_free(fuse_lock_group);
        fuse_lock_group = NULL;
    }

    if (fuse_malloc_tag) {
        OSMalloc_Tagfree(fuse_malloc_tag);
        fuse_malloc_tag = NULL;
    }

    if (fuse_lock_attr) {
        lck_attr_free(fuse_lock_attr);
        fuse_lock_attr = NULL;
    }

    if (fuse_group_attr) {
        lck_grp_attr_free(fuse_group_attr);
        fuse_group_attr = NULL;
    }
}

static kern_return_t
init_stuff(void)
{
    kern_return_t ret = KERN_SUCCESS;
    
    fuse_malloc_tag = OSMalloc_Tagalloc(MACFUSE_BUNDLE_IDENTIFIER,
                                        OSMT_DEFAULT);
    if (fuse_malloc_tag == NULL) {
        ret = KERN_FAILURE;
    }

    fuse_lock_attr = lck_attr_alloc_init();
    fuse_group_attr = lck_grp_attr_alloc_init();
    lck_attr_setdebug(fuse_lock_attr);

    if (ret == KERN_SUCCESS) {
        fuse_lock_group = lck_grp_alloc_init(MACFUSE_BUNDLE_IDENTIFIER,
                                             fuse_group_attr);
        if (fuse_lock_group == NULL) {
            ret = KERN_FAILURE;
        }
    }

    if (ret == KERN_SUCCESS) {
        fuse_device_mutex = lck_mtx_alloc_init(fuse_lock_group, fuse_lock_attr);
        if (fuse_device_mutex == NULL) {
            ret = ENOMEM;
        }
    }

#if M_MACFUSE_ENABLE_INTERIM_FSNODE_LOCK
#if M_MACFUSE_ENABLE_LOCK_LOGGING
    if (ret == KERN_SUCCESS) {
        fuse_log_lock = lck_mtx_alloc_init(fuse_lock_group, fuse_lock_attr);
        if (fuse_log_lock == NULL) {
            ret = ENOMEM;
        }
    }
#endif /* M_MACFUSE_ENABLE_LOCK_LOGGING */

#if M_MACFUSE_ENABLE_HUGE_LOCK
    if (ret == KERN_SUCCESS) {
        fuse_huge_lock = fusefs_recursive_lock_alloc();
        if (fuse_huge_lock == NULL) {
            ret = ENOMEM;
        }
    }
#endif /* M_MACFUSE_ENABLE_HUGE_LOCK */
#endif /* M_MACFUSE_ENABLE_INTERIM_FSNODE_LOCK */

    if (ret != KERN_SUCCESS) {
        fini_stuff();
    }

    return ret;
}

kern_return_t
fusefs_start(__unused kmod_info_t *ki, __unused void *d)
{
    int ret;

    ret = init_stuff();
    if (ret != KERN_SUCCESS) {
        return KERN_FAILURE;
    }

    ret = HNodeInit(fuse_lock_group, fuse_lock_attr, fuse_malloc_tag,
                    kHNodeMagic, sizeof(struct fuse_vnode_data));
    if (ret != KERN_SUCCESS) {
        goto error;
    }

    ret = vfs_fsadd(&fuse_vfs_entry, &fuse_vfs_table_ref);
    if (ret != 0) {
        fuse_vfs_table_ref = NULL;
        goto error;
    }

    ret = fuse_devices_start();
    if (ret != KERN_SUCCESS) {
        goto error;
    }

    fuse_sysctl_start();

    IOLog("MacFUSE: starting (version %s, %s)\n",
          MACFUSE_VERSION, MACFUSE_TIMESTAMP);

    return KERN_SUCCESS;

error:
    if (fuse_vfs_table_ref) {
        (void)vfs_fsremove(fuse_vfs_table_ref);
    }
    HNodeTerm();
    fini_stuff();

    return KERN_FAILURE;
}

kern_return_t
fusefs_stop(__unused kmod_info_t *ki, __unused void *d)
{
    int ret;

    ret = fuse_devices_stop();
    if (ret != KERN_SUCCESS) {
        return KERN_FAILURE;
    }

    ret = vfs_fsremove(fuse_vfs_table_ref);
    if (ret != KERN_SUCCESS) {
        return KERN_FAILURE;
    }

    HNodeTerm();
    fini_stuff();

    fuse_sysctl_stop();

    IOLog("MacFUSE: stopping (version %s, %s)\n",
          MACFUSE_VERSION, MACFUSE_TIMESTAMP);

    return KERN_SUCCESS;
}
