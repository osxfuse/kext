/*
 * Copyright (C) 2006-2008 Google. All Rights Reserved.
 * Amit Singh <singh@>
 */

/*
 * Portions Copyright (c) 1999-2003 Apple Computer, Inc. All Rights Reserved.
 *
 * This file contains Original Code and/or Modifications of Original Code as
 * defined in and that are subject to the Apple Public Source License Version
 * 2.0 (the 'License'). You may not use this file except in compliance with
 * the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT. Please see
 * the License for the specific language governing rights and limitations
 * under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/sysctl.h>

#include <grp.h>
#include <string.h>

#include <CoreServices/CoreServices.h>

#include <fuse_param.h>
#include <fuse_version.h>

#if OSXFUSE_ENABLE_MACFUSE_MODE
#define OSXFUSE_MACFUSE_MODE_ENV  "OSXFUSE_MACFUSE_MODE"
#define OSXFUSE_KEXT_MACFUSE_MODE "osxfuse.control.macfuse_mode"
#endif

int
main(__unused int argc, __unused const char *argv[])
{
    int    pid = -1;
    int    result = -1;
    union  wait status;
    char   version[MAXHOSTNAMELEN + 1] = { 0 };
    size_t version_len = MAXHOSTNAMELEN;
    size_t version_len_desired = 0;
    struct vfsconf vfc = { 0 };

    result = getvfsbyname(OSXFUSE_FS_TYPE, &vfc);
    if (result) { /* OSXFUSE is not already loaded */
        result = -1;
        goto need_loading;
    }

    /* some version of OSXFUSE is already loaded; let us check it out */

    result = sysctlbyname(SYSCTL_OSXFUSE_VERSION_NUMBER, version,
                          &version_len, NULL, (size_t)0);
    if (result) {
        if (errno == ENOENT) {
            /* too old; doesn't even have the sysctl variable */
            goto need_unloading;
        }
        result = -1;
        goto out;
    }

    /* sysctlbyname() includes the trailing '\0' in version_len */
    version_len_desired = strlen(OSXFUSE_VERSION) + 1;

    if ((version_len == version_len_desired) &&
        !strncmp(OSXFUSE_VERSION, version, version_len)) {
        /* what's currently loaded is good */
        result = 0;
        goto out;
    }

    /* mismatched version; need to unload what's loaded */

need_unloading:
    pid = fork();
    if (pid == 0) {
        result = execl(SYSTEM_KEXTUNLOAD, SYSTEM_KEXTUNLOAD, "-b",
                       OSXFUSE_BUNDLE_IDENTIFIER, NULL);
        /* We can only get here if the exec failed */
        goto out;
    }

    if (pid == -1) {
        result = errno;
        goto out;
    }

    /* Success! */
    if ((wait4(pid, (int *)&status, 0, NULL) == pid) && (WIFEXITED(status))) {
        result = status.w_retcode;
    } else {
        result = -1;
    }

    if (result != 0) {
        /* unloading failed */
        result = EBUSY;
        goto out;
    }

    /* unloading succeeded; now load the on-disk version */

need_loading:
    pid = fork();
    if (pid == 0) {
        SInt32 system_version_major, system_version_minor;
        char *kext_path;

        if ((Gestalt(gestaltSystemVersionMajor, &system_version_major) != noErr) ||
            (Gestalt(gestaltSystemVersionMinor, &system_version_minor) != noErr)) {
            result = ENOENT;
            goto out;
        }

        result = asprintf(&kext_path, "%s/%ld.%ld/%s", OSXFUSE_SUPPORT_PATH,
                          (long) system_version_major, (long) system_version_minor,
                          OSXFUSE_KEXT_NAME);
        if (result == -1) {
            result = ENOENT;
            goto out;
        }

        result = execl(SYSTEM_KEXTLOAD, SYSTEM_KEXTLOAD, kext_path, NULL);
        /* We can only get here if the exec failed */
        goto out;
    }

    if (pid == -1) {
        result = errno;
        goto out;
    }

    /* Success! */
    if ((wait4(pid, (int *)&status, 0, NULL) == pid) && (WIFEXITED(status))) {
        result = status.w_retcode;
    } else {
        result = -1;
    }

    /* now do any kext-load-time settings we need to do as root */

    if (result == 0) {
        int admin_gid = 0;
        struct group *g = getgrnam(MACOSX_ADMIN_GROUP_NAME);
        if (!g) {
            goto out;
        }
        admin_gid = g->gr_gid;

        /* if this fails, we don't care */
        (void)sysctlbyname(SYSCTL_OSXFUSE_TUNABLES_ADMIN, NULL, NULL,
                          &admin_gid, sizeof(admin_gid));
    }

out:
#if OSXFUSE_ENABLE_MACFUSE_MODE
    {
        char *env_value;
        env_value = getenv(OSXFUSE_MACFUSE_MODE_ENV);
        if (env_value != NULL && strcmp(env_value, "1") == 0) {
            int32_t enabled = 1;
            size_t  length = 4;
            sysctlbyname(OSXFUSE_KEXT_MACFUSE_MODE, NULL, 0, &enabled, length);
        }
    }
#endif

    _exit(result);
}
