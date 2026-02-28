/*
    This file is heavily based on library_injector.cpp by Saagar Jha
    https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f
    SPDX-License-Identifier: LGPL-3.0-only
*/

#include <sys/types.h>
#include <stdbool.h>


// Logging is a complicated mess on macOS.
//
// Although os_log() is suppose to be the preferred solution, it lacks basic
// functionality like va_list support or redirection to stdout/stderr.
//
// Hence, everybody writes their own wrappers.
//
typedef enum {
    InjectionLogLevelDebug,   // arm64 register information, hex dumps
    InjectionLogLevelDefault, // Information about what the injector is doing
    InjectionLogLevelError    // Errors
} InjectionLogLevel;

typedef void (^InjectionLogCallback)(InjectionLogLevel level, const char *format, ...);

void InjectionSetLogCallback(InjectionLogCallback callback);

// Perform actual injection
bool InjectionInjectIntoProcess(
    pid_t       pid,
    const char *dyldLibraryPath,
    const char *dyldFrameworkPath,
    const char *dyldInsertLibraries
);
