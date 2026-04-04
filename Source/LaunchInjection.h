/*
    This file is heavily based on library_injector.cpp by Saagar Jha
    https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f
    SPDX-License-Identifier: LGPL-3.0-only
*/

#ifndef LAUNCH_INJECTION_H
#define LAUNCH_INJECTION_H

#include <sys/types.h>
#include <stdbool.h>


/*
    Logging is a complicated mess on macOS.
    
    Although os_log() is suppose to be the preferred solution, it lacks basic
    functionality like va_list support or redirection to stdout/stderr.

    Hence, everybody writes their own wrappers.
*/
typedef enum {
    LaunchInjectionLogLevelDebug,   // arm64 register information, hex dumps
    LaunchInjectionLogLevelDefault, // Information about what the injector is doing
    LaunchInjectionLogLevelError    // Errors
} LaunchInjectionLogLevel;

typedef void (^LaunchInjectionLogCallback)(LaunchInjectionLogLevel level, const char *format, ...);

void LaunchInjectionSetLogCallback(LaunchInjectionLogCallback callback);


/*
    Basic API, used by demo.
    Will append libraryPath to DYLD_INSERT_LIBRARIES and set DYLD_SHARED_REGION to 1.
*/
bool LaunchInjectionInjectLibrary(pid_t pid, const char *libraryPath);


/*
    Advanced API, allows finer-grained manipulation of environmental variables.
    Each InjectionVariable parameter should be terminated with { NULL, NULL }.
*/
typedef struct LaunchInjectionVariable {
    const char *key;
    const char *value;
} LaunchInjectionVariable;

bool LaunchInjectionModifyEnvironment(
    pid_t pid,
    
    // Prepends to existed variables using a ':' separator
    const LaunchInjectionVariable *prependPathVariables,

    // Appends to existed variables using a ':' separator
    const LaunchInjectionVariable *appendPathVariables,

    // Overwrites any existing variables
    const LaunchInjectionVariable *overwriteVariables
);

#endif /* LAUNCH_INJECTION_H */
