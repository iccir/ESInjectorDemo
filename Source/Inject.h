/*
    This file is heavily based on library_injector.cpp by Saagar Jha
    https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f
    SPDX-License-Identifier: LGPL-3.0-only
*/

#include <sys/types.h>
#include <stdbool.h>
#include <os/log.h>

void SetLogger(os_log_t logger);
void LogInfo(char *format, ...);
void LogError(char *format, ...);

boolean_t InjectIntoProcess(
    pid_t       pid,
    const char *dyldLibraryPath,
    const char *dyldFrameworkPath,
    const char *dyldInsertLibraries
);
