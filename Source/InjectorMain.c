/*
    This file is heavily based on library_injector.cpp by Saagar Jha
    https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f
    SPDX-License-Identifier: LGPL-3.0-only
*/

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <mach-o/dyld.h>
#include <sys/ptrace.h>
#include <assert.h>
#include <string.h>

#include "Inject.h"

static void sLog(FILE * f, char *format, ...)
{
    va_list v;
    va_start(v, format);
    
    vfprintf(f, format, v);
    fprintf(f, "\n");

    va_end(v);
}

#define sLogStdout(...) sLog(stdout, ##__VA_ARGS__)
#define sLogStderr(...) sLog(stderr, ##__VA_ARGS__)




/*
    Adds DYLD_SHARED_REGION=1 to environment and re-executes via execve()
*/
static void sExecWithoutDyldInCache(int argc, char **argv, char **inEnvp)
{
    uint32_t length = 0;
    _NSGetExecutablePath(NULL, &length);

    char *path = (char *)alloca(length);
    _NSGetExecutablePath(path, &length);

    int envc = 0;
    while (inEnvp[envc]) envc++;
    char **envp = (char **)alloca((envc + 2) * sizeof(char *));

    memcpy(envp, inEnvp, envc * sizeof(char *));

    envp[envc]     = "DYLD_SHARED_REGION=1";
    envp[envc + 1] = NULL;

    execve(path, argv, envp);
}


int main(int argc, char **argv, char **envp)
{
    InjectionSetLogCallback(^(InjectionLogLevel level, const char *format, ...) {
        va_list v;
        va_start(v, format);

        FILE *f = (level == InjectionLogLevelError) ? stderr : stdout;
        vfprintf(f, format, v);
        fprintf(f, "\n");

        va_end(v);
    });

    if (argc != 3) {
        fprintf(stderr, "Usage: Injector library_to_inject path_to_match\n");
        return 1;
    }

	if (!getenv("DYLD_SHARED_REGION")) {
        sLogStdout("DYLD_SHARED_REGION not set, re-executing.");
        sExecWithoutDyldInCache(argc, argv, envp);
        assert(false);
	}

	char *library = argv[1];
    char *pathToMatch = argv[2];
    unsigned long err;

	es_client_t *client = NULL;
	err = es_new_client(&client, ^(es_client_t *client, const es_message_t *message) {
		if (message->event_type != ES_EVENT_TYPE_AUTH_EXEC) {
            sLogStderr("Received es_message_t of type: %u", message->event_type);
            return;
        }

        const char *name = message->event.exec.target->executable->path.data;
            
        pid_t pid = audit_token_to_pid(message->process->audit_token);

        /*
            This is a simplified version of Saagar's logic:
            
            1) He uses csops() to get CS_OPS_STATUS, then checks for the
               CS_ENFORCEMENT bit. If set, he uses ptrace() to set CS_DEBUGGED.
               This is only needed for iOS-on-Mac apps, which he needs to
               inject his ios_scaler:
               https://github.com/saagarjha/dotfiles/blob/master/ios_scaler.mm

            2) He checks the P_TRANSLATED bit of both the injector and the
               injectee. Injection only occurs if the bits are the same.
               I believe that this is needed for Rosetta binaries, but I'm
               not sure.

            3) He uses regexp to check paths, this demo only supports basic
               substring matching.
        */
        if (strnstr(name, pathToMatch, strlen(name)) > 0) {
            sLogStdout("Matched pid %ld at '%s', injecting payload.", (long)pid, name);

            uint64_t startTime = mach_absolute_time();

            if (InjectionInjectIntoProcess(pid, NULL, NULL, library)) {
                mach_timebase_info_data_t timebase;
                mach_timebase_info(&timebase);

                uint64_t elapsed = (mach_absolute_time() - startTime) * timebase.numer / timebase.denom;
            
                sLogStdout("Injection into pid %ld successful, elapsed time: %ldms\n", (long)pid, (long)(elapsed / 1000000));

            } else {
                sLogStderr("Injection into pid %ld failed", (long)pid);
            }
        }

        es_respond_result_t err = es_respond_auth_result(client, message, ES_AUTH_RESULT_ALLOW, false);
        if (err) {
            sLogStderr("es_respond_auth_result() failed, error = %ld", (long)err);
        }
	});
    
    if (err) {
        sLogStderr("es_new_client() failed, error = %ld", (long)err);
        return 1;
    }
    
	es_event_type_t events[] = { ES_EVENT_TYPE_AUTH_EXEC };
    err = es_subscribe(client, events, sizeof(events) / sizeof(es_event_type_t));
    
    if (err) {
        sLogStderr("es_subscribe() failed, error = %ld", (long)err);
        return 1;
    }
    
	dispatch_main();
}
