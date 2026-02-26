/*
    This file is heavily based on library_injector.cpp by Saagar Jha
    https://gist.github.com/saagarjha/a70d44951cb72f82efee3317d80ac07f
    SPDX-License-Identifier: LGPL-3.0-only
*/

#include "Inject.h"

#include <sys/sysctl.h>
#include <sys/errno.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


// The current code adds a maximum of 4 environment variables to the stack.
// DYLD_LIBRARY_PATH, DYLD_FRAMEWORK_PATH, DYLD_INSERT_LIBRARIES, DYLD_SHARED_REGION
//
#define ENVP_EXTRA_CAPACITY 4


// exec_copyout_strings in kern_exec.c has an ASCII diagram with a
// box labelled "16b". It *looks* like this indicates some kind of padding
// between the "STRING AREA" and p->user_stack; however, it could also mean
// alignment.
//
// In any case, on Sonoma, there is no padding present and the end of
// STRING AREA can be p->user_stack.
//
// Set this variable if extra padding is desired.
//
#define STRING_AREA_EXTRA_PADDING 0


#pragma mark - Logging

char sLogBuffer[1024];

static os_log_t sLogger = NULL;

boolean_t sShouldLogInfo(void)
{
    return !sLogger || os_log_type_enabled(sLogger, OS_LOG_TYPE_INFO);
}


void LogInfo(char *format, ...)
{
    if (!sShouldLogInfo()) return;

    va_list v;
    va_start(v, format);
    
    vsnprintf(sLogBuffer, sizeof(sLogBuffer), format, v);

    if (sLogger) {
        os_log_info(sLogger, "%s", sLogBuffer);
    } else {
        fprintf(stdout, "%s\n", sLogBuffer);
    }

    va_end(v);
}


void LogError(char *format, ...)
{
    if (sLogger && !os_log_type_enabled(sLogger, OS_LOG_TYPE_ERROR)) return;

    va_list v;
    va_start(v, format);
    
    vsnprintf(sLogBuffer, sizeof(sLogBuffer), format, v);
    
    if (sLogger) {
        os_log_error(sLogger, "%s", sLogBuffer);
    } else {
        fprintf(stderr, "%s\n", sLogBuffer);
    }

    va_end(v);
}


void sLogThreadState(const arm_thread_state64_t *state)
{
    LogInfo(
        "Thread State:\n"
        "   x0: 0x%016llx   x1: 0x%016llx   x2: 0x%016llx   x3: 0x%016llx\n"
        "   x4: 0x%016llx   x5: 0x%016llx   x6: 0x%016llx   x7: 0x%016llx\n"
        "   x8: 0x%016llx   x9: 0x%016llx  x10: 0x%016llx  x11: 0x%016llx\n"
        "  x12: 0x%016llx  x13: 0x%016llx  x14: 0x%016llx  x15: 0x%016llx\n"
        "  x16: 0x%016llx  x17: 0x%016llx  x18: 0x%016llx  x19: 0x%016llx\n"
        "  x20: 0x%016llx  x21: 0x%016llx  x22: 0x%016llx  x23: 0x%016llx\n"
        "  x24: 0x%016llx  x25: 0x%016llx  x26: 0x%016llx  x27: 0x%016llx\n"
        "  x28: 0x%016llx   fp: 0x%016llx   lr: 0x%016llx\n"
        "   sp: 0x%016llx   pc: 0x%016llx cpsr: 0x%08x\n",
        state->__x[0],  state->__x[1],  state->__x[2],  state->__x[3],
        state->__x[4],  state->__x[5],  state->__x[6],  state->__x[7],
        state->__x[8],  state->__x[9],  state->__x[10], state->__x[11],
        state->__x[12], state->__x[13], state->__x[14], state->__x[15],
        state->__x[16], state->__x[17], state->__x[18], state->__x[19],
        state->__x[20], state->__x[21], state->__x[22], state->__x[23],
        state->__x[24], state->__x[25], state->__x[26], state->__x[27],
        state->__x[28],
        arm_thread_state64_get_fp(*state),
        arm_thread_state64_get_lr(*state),
        arm_thread_state64_get_sp(*state),
        arm_thread_state64_get_pc(*state),
        state->__cpsr
    );
}


static void sLogHexDump(vm_address_t address, const void *data, size_t size)
{
    if (!sShouldLogInfo()) return;

    const unsigned char *bytes = (const unsigned char *)data;

    __block size_t offset       = 0;
    size_t length = 1024;
    char *line = alloca(length);

    __auto_type append = ^(char *format, ...) {
        if (offset > length) return;

        va_list v;
        va_start(v, format);
        offset += vsnprintf(line + offset, length - offset, format, v);
        va_end(v);
    };

    for (size_t i = 0; i < size; i += 16) {
        offset = 0;

        // Print offset in first column
        append("%016lx  ", address + i);

        // Print hex bytes in middle area
        for (size_t j = 0; j < 16; j++) {
            if (i + j < size) {
                append("%02x ", bytes[i + j]);
            } else {
                append("   ");
            }

            if (j == 7) {
                append(" ");
            }
        }

        // Print ASCII area
        {
            append(" |");
            size_t j;

            for (j = 0; j < 16 && i + j < size; j++) {
                unsigned char c = bytes[i + j];
                append("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
            }
            
            for ( ; j < 16; j++) {
                append(" ");
            }
            
            append("|");
        }

        LogInfo("%s", line);
    }
}


#pragma mark - Structs

typedef struct StackString {
    vm_address_t address; // Remote address
    char *buffer;
} StackString;


typedef struct StackList {
    size_t count;
    size_t capacity;
    StackString *strings;
} StackList;


typedef struct Stack {
    uintptr_t loadAddress;
    uintptr_t argc;
    StackList *argvList;
    StackList *envpList;
    StackList *applevList;
    vm_address_t user_stack; // Remote address of end of user_stack
} Stack;


static StackList *sCreateList(size_t capacity)
{
    StackList *list = calloc(1, sizeof(StackList));

    list->capacity = capacity;
    list->count = 0;
    list->strings = calloc(list->capacity, sizeof(StackString));

    return list;
}


static void sFreeList(StackList *list)
{
    if (!list) return;
    
    for (int i = 0; i < list->count; i++) {
        free(list->strings[i].buffer);
    }
    
    free(list);
}


static Stack *sCreateStack(void)
{
    Stack *stack = calloc(1, sizeof(Stack));
    return stack;
}


static void sFreeStack(Stack *stack)
{
    sFreeList(stack->argvList);
    sFreeList(stack->envpList);
    sFreeList(stack->applevList);

    free(stack);
}


static void sStackIterateLists(Stack *stack, void (^callback)(StackList *list))
{
    StackList *lists[3] = { stack->argvList, stack->envpList, stack->applevList };

    for (size_t i = 0; i < 3; i++) {
        callback(lists[i]);
    }
}


static void sListIterateStrings(StackList *list, void (^callback)(StackString *string))
{
    for (size_t i = 0; i < list->count; i++) {
        callback(&list->strings[i]);
    }
}


#pragma mark - Private Functions

/*
    Writes a buffer of memory to the remote task
*/
static boolean_t sWriteBuffer(task_t task, vm_address_t address, const void *buffer, size_t size)
{
    kern_return_t err = KERN_SUCCESS;
    
    vm_address_t protectAddress = trunc_page(address);
    vm_size_t    protectSize    = round_page(address + size) - protectAddress;
    
    vm_prot_t readWriteCopy = VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY;
    vm_prot_t readExecute   = VM_PROT_READ | VM_PROT_EXECUTE;

    if ((err = vm_protect(task, protectAddress, protectSize, false, readWriteCopy)) != KERN_SUCCESS) {
        LogError("vm_protect(... readWriteCopy) failed, error: %ld", (long)err);
        return false;
    }

    if ((err = vm_write(task, address, (vm_offset_t)buffer, (mach_msg_type_number_t)size)) != KERN_SUCCESS) {
        LogError("vm_write() failed, error: %ld", (long)err);
        return false;
    }
    
    if ((err = vm_protect(task, protectAddress, protectSize, false, readExecute)) != KERN_SUCCESS) {
        LogError("vm_protect(... readExecute) failed, error: %ld", (long)err);
        return false;
    }
    
    return true;
}


/*
    Writes our amfi_check_dyld_policy_self() patch.
    This ensures that AMFI_DYLD_OUTPUT_ALLOW_LIBRARY_INTERPOSING is enabled.
*/
static boolean_t sWriteAMFICheckPolicyPatch(task_t task, vm_address_t address)
{
    const uint8_t replacement[] = {
        0xe2, 0x0b, 0x80, 0xd2, // mov x2, #0x5f
        0x22, 0x00, 0x00, 0xf9, // str x2, [x1]
        0x00, 0x00, 0x80, 0xd2, // mov x0, #0
        0xc0, 0x03, 0x5f, 0xd6, // ret
    };
    
    if (!sWriteBuffer(task, address, replacement, sizeof(replacement))) {
        LogError("sWriteAMFICheckPolicyPatch() failed due to sWriteBuffer() returning false");
        return false;
    }

    return true;
}


/*
    Generates our _dyld_start patch based on 'difference', then
    patches it via sWriteBuffer()
*/
static boolean_t sWriteDyldStartPatch(task_t task, vm_address_t address, uint64_t difference)
{
    uint8_t replacement[] = {
        0xff, 0x03, 0x00, 0xd1, // sub sp, sp, 0            ; 0 will be filled in below
        0xff, 0x03, 0x40, 0xd1, // sub sp, sp, 0, lsl 12    ; 0 will be filled in below
        0xe0, 0x03, 0x00, 0x91, // mov x0, sp
        
        // sp is already aligned to a 16-byte boundary in sWriteStack()
        // Hence, we don't need the following instruction:
        // 0x1f, 0xec, 0x7c, 0x92, // and sp, x0, #~15
    };

    LogInfo("Writing _dyld_start() patch to %p, difference=%llu\n", address, difference);

    // We only know how to handle a difference of 24-bits
    if ((difference >> 24) > 0) {
        LogError("sWriteDyldStartPatch() failed, difference of %ld exceeds 24-bit limit.", (long)difference);
        return false;
    }

    // Each sub instruction takes a 12-bit immediate value. Mask and shift difference.
    replacement[1] |= ( (difference        & 0x03f) << 2);
    replacement[2] |= ( (difference        & 0xfc0) >> 6);

    replacement[5] |= (((difference >> 12) & 0x03f) << 2);
    replacement[6] |= (((difference >> 12) & 0xfc0) >> 6);

    if (!sWriteBuffer(task, address, replacement, sizeof(replacement))) {
        LogError("sWriteDyldStartPatch() failed due to sWriteBuffer() returning false");
        return false;
    }
    
    return true;
}


/*
    Checks that _dyld_start contains the expected instructions.
*/
static boolean_t sCheckDyldStart(task_t task, vm_address_t address)
{
    const uint8_t expected[] = {
        0xe0, 0x03, 0x00, 0x91, // mov x0, sp
        0x1f, 0xec, 0x7c, 0x92, // and sp, x0, #~15
        0x1d, 0x00, 0x80, 0xd2, // mov fp, #0
        0x1e, 0x00, 0x80, 0xd2  // mov lr, #0
    };

    uint8_t actual[sizeof(expected)];

    vm_size_t bytesToRead = sizeof(actual);
    vm_size_t bytesRead   = bytesToRead;
    
    kern_return_t err = vm_read_overwrite(task, address, bytesToRead, (vm_address_t)&actual, &bytesRead);

    if (err != KERN_SUCCESS) {
        LogError("sCheckDyldStart: vm_read_overwrite() failed, error = %ld", (long)err);
        return false;
    }
    
    if (bytesRead != sizeof(actual)) {
        LogError("sCheckDyldStart: vm_read_overwrite() read wrong size: %ld != %ld", bytesRead, bytesToRead);
        return false;
    }

    if (memcmp(expected, actual, sizeof(actual)) != 0) {
        LogError("sCheckDyldStart: expected != actual");
        return false;
    }

    return true;
}


/*
    Finds the address of amfi_check_dyld_policy_self() in the remote task
*/
static boolean_t sFindAMFICheckPolicy(task_t task, uintptr_t pc, vm_address_t *outAddress)
{
	task_dyld_info_data_t dyldInfo;
	mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
 
    kern_return_t err = task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&dyldInfo, &count);
    
    if (err != KERN_SUCCESS) {
        LogError("task_info(...TASK_DYLD_INFO...) failed, error = %ld", (long)err);
        return false;
    }

	struct dyld_all_image_infos *allImageInfos = (struct dyld_all_image_infos *)dyldInfo.all_image_info_addr;
	struct mach_header_64       *header        = (struct mach_header_64 *)allImageInfos->dyldImageLoadAddress;

	uintptr_t base = (uintptr_t) header;
	uintptr_t ptr  = (uintptr_t)(header + 1);

    uintptr_t _dyld_start = 0;
    uintptr_t amfi_check_dyld_policy_self = 0;

	for (size_t i = 0; (i < header->ncmds) && !_dyld_start && !amfi_check_dyld_policy_self; i++) {
		struct load_command *loadCommand = (struct load_command *)ptr;

		if (loadCommand->cmd == LC_SYMTAB) {
			struct symtab_command *symTabCommand = (struct symtab_command *)loadCommand;
            struct nlist_64       *symbols       = (struct nlist_64 *)(base + symTabCommand->symoff);

            for (size_t j = 0; j < symTabCommand->nsyms; j++) {
                char *symbolName = (char *)((base + symTabCommand->stroff) + symbols[j].n_un.n_strx);
                
                if (strcmp("__dyld_start", symbolName) == 0) {
                    _dyld_start = symbols[j].n_value;
                } else if (strcmp("_amfi_check_dyld_policy_self", symbolName) == 0) {
                    amfi_check_dyld_policy_self = symbols[j].n_value;
                }
            }
		}

		ptr += loadCommand->cmdsize;
	}

    if (!_dyld_start) {
        LogError("sFindAMFICheckPolicy() failed due to missing _dyld_start address");
        return false;
    }
    
    if (!amfi_check_dyld_policy_self) {
        LogError("sFindAMFICheckPolicy() failed due to missing amfi_check_dyld_policy_self address");
        return false;
    }

    // We are stopped in _dyld_start(), so pc should point to it.
    // Calculate location of amfi_check_dyld_policy_self() via basic math.
    vm_address_t my_amfi_check_dyld_policy_self = pc + (amfi_check_dyld_policy_self - _dyld_start);

    LogInfo("Symbol table values:\n    amfi_check_dyld_policy_self: %p\n    _dyld_start: %p\n",
        amfi_check_dyld_policy_self, _dyld_start
    );
    
    LogInfo("Computed location of amfi_check_dyld_policy_self: %p\n", my_amfi_check_dyld_policy_self);

    *outAddress = my_amfi_check_dyld_policy_self;

    return true;
}


/*
    Reads the remote region of memory from sp to end-of-region
    and constructs our Stack struct.
*/
static boolean_t sReadStack(task_port_t task, vm_address_t sp, Stack **outStack)
{
    __block boolean_t ok = true;

    __block size_t scanOffset = 0;

    __block void *remoteBuffer = NULL;
    __block vm_size_t remoteLength = 0;
    
    vm_address_t user_stack;
    
    __auto_type readStringBuffer = ^(uintptr_t address) {
        size_t offset = address - sp;

        size_t length = strnlen(remoteBuffer + offset, remoteLength - offset);
        
        char *str = malloc(length + 1);
        strncpy(str, remoteBuffer + offset, length);
        return str;
    };
    
    __auto_type scanPointer = ^() {
        uintptr_t result = *(uintptr_t *)(remoteBuffer + scanOffset);
        scanOffset += sizeof(uintptr_t);
        return result;
    };
    
    __auto_type scanList = ^(size_t extra) {
        size_t savedOffset = scanOffset;
        size_t count = 0;
        
        while (ok && scanPointer()) count++;

        StackList *list = sCreateList(count + extra);

        scanOffset = savedOffset;
        for (size_t i = 0; i < count; i++) {
            uintptr_t address = scanPointer();

            list->strings[i].address = address;
            list->strings[i].buffer = readStringBuffer(address);
            list->count++;
        }
        scanPointer();
        
        return list;
    };

    // Read remote stack into remoteBuffer/remoteLength
    {
        vm_address_t regionAddr = (vm_address_t)sp;
        vm_size_t regionSize;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objectName;
        kern_return_t err;
        
        err = vm_region_64(
            task, &regionAddr, &regionSize,
            VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count,
            &objectName
        );

        if (err != KERN_SUCCESS) {
            LogError("vm_read() failed, error = %ld", (long)err);
            return false;
        }

        user_stack = (regionAddr + regionSize);

        mach_msg_type_number_t bytesToRead = (mach_msg_type_number_t)(user_stack - sp);
        mach_msg_type_number_t bytesRead   = bytesToRead;

        err = vm_read(task, sp, bytesToRead, (vm_offset_t *)&remoteBuffer, &bytesRead);
        remoteLength = bytesRead;
        
        LogInfo("Memory from sp to end of region:");
        sLogHexDump(sp, remoteBuffer, bytesRead);

        if (err != KERN_SUCCESS) {
            LogError("vm_read() failed, error = %ld", (long)err);
            return false;

        } else if (bytesRead != bytesToRead) {
            LogError("vm_read() read wrong size of %u, expected %u", bytesRead, bytesToRead);
            return false;
        }
    }

    // Scan remoteBuffer and build Stack object
    Stack *stack = sCreateStack();

    stack->loadAddress = scanPointer();
    stack->argc        = scanPointer();
    stack->argvList    = scanList(0);
    stack->envpList    = scanList(ENVP_EXTRA_CAPACITY);
    stack->applevList  = scanList(0);
    stack->user_stack  = user_stack;

    // Deallocate buffer from vm_read
    {
        kern_return_t err = vm_deallocate(mach_task_self(), (vm_address_t)remoteBuffer, remoteLength);

        if (err != KERN_SUCCESS) {
            LogError("vm_deallocate() failed, error = %ld", (long)err);
            sFreeStack(stack);

            return false;
        }
    }
    
    *outStack = stack;

    return true;
}


/*
    Modifies the Stack struct to add environment variables
*/
static boolean_t sModifyStack(
    task_port_t task, Stack *stack,
    const char *dyldLibraryPath,
    const char *dyldFrameworkPath,
    const char *dyldInsertLibraries
) {
    __auto_type getStringWithPrefix = ^(StackList *list, const char *prefix) {
        StackString *foundString = NULL;
        size_t needleLength = strlen(prefix);

        for (int i = 0; i < list->count; i++) {
            StackString *string = &list->strings[i];

            if (!string) continue;
            if (strlen(string->buffer) < needleLength) continue;

            if (strncmp(string->buffer, prefix, needleLength) == 0) {
                foundString = string;
                break;
            }
        }
        
        return foundString;
    };
    
    __auto_type replaceContents = ^(StackString *string, const char *prefix, const char *value) {
        size_t length = strlen(prefix) + strlen(value) + 1;
        free(string->buffer);
        string->buffer = malloc(length);
        snprintf(string->buffer, length, "%s%s", prefix, value);
    };
    
    __auto_type appendString = ^(StackList *list, const char *prefix, const char *value) {
        assert(list->count < list->capacity);
        replaceContents(&list->strings[list->count], prefix, value);
        list->count++;
    };

    __auto_type appendPathValue = ^(StackList *list, const char *prefix, const char *value) {
        StackString *string = getStringWithPrefix(list, prefix);
        
        if (string) {
            size_t length = strlen(string->buffer) + strlen(value) + 2;
            char *newBuffer = malloc(length);
            snprintf(newBuffer, length, "%s:%s", string->buffer, value);

            free(string->buffer);
            string->buffer = newBuffer;

        } else {
            appendString(list, prefix, value);
        }
    };

    if (dyldLibraryPath) {
        appendPathValue(stack->envpList, "DYLD_LIBRARY_PATH=", dyldLibraryPath);
    }

    if (dyldFrameworkPath) {
        appendPathValue(stack->envpList, "DYLD_FRAMEWORK_PATH=", dyldFrameworkPath);
    }

    if (dyldInsertLibraries) {
        appendPathValue(stack->envpList, "DYLD_INSERT_LIBRARIES=", dyldInsertLibraries);
    }

    // Ensure DYLD_SHARED_REGION=1 to disable dyld-in-cache
    {
        StackString *dyldSharedRegion = getStringWithPrefix(stack->envpList, "DYLD_SHARED_REGION=");

        if (dyldSharedRegion) {
            replaceContents(dyldSharedRegion, "DYLD_SHARED_REGION=", "1");
        } else {
            appendString(stack->envpList, "DYLD_SHARED_REGION=", "1");
        }
    }

    return true;
}


/*
    Writes our (manipulated) Stack struct back into the remote process.
    Returns the new stack pointer.
*/
static boolean_t sWriteStack(task_port_t task, Stack *stack, uintptr_t *outSp)
{
    __block vm_address_t sp = stack->user_stack;
    __block size_t stringCount = 0;
    __block size_t stringAreaLength = 0;

    // Add extra 0x00 bytes if STRING_AREA_EXTRA_PADDING (shouldn't be needed)
    sp -= STRING_AREA_EXTRA_PADDING;
    stringAreaLength += STRING_AREA_EXTRA_PADDING;
    
    sStackIterateLists(stack, ^(StackList *list) {
        sListIterateStrings(list, ^(StackString *string) {
            size_t length = strlen(string->buffer) + 1;
            sp -= length;
            stringAreaLength += length;
            stringCount++;
        });
    });

    // Align to pointer boundary
    sp = (sp / sizeof(uintptr_t)) * sizeof(uintptr_t);
    
    vm_address_t stringAreaStart = sp;
    
    // Move down for itemCount pointers, plus 3 NULL separators, argc, and loadAddress
    sp -= (stringCount + 3 + 1 + 1) * sizeof(uintptr_t);

    // Align stack to 16-byte boundary
    sp = sp & ~0xF;

    size_t bufferLength = stack->user_stack - sp;
    void  *buffer = calloc(1, bufferLength);

    // Write strings area
    {
        __block size_t bufferOffset = stringAreaStart - sp;
        
        sStackIterateLists(stack, ^(StackList *list) {
            sListIterateStrings(list, ^(StackString *string) {
                string->address = sp + bufferOffset;

                size_t length = strlen(string->buffer);
                memcpy(buffer + bufferOffset, string->buffer, length);
                bufferOffset += length + 1;
            });
        });
    }
    
    // Write pointer area
    {
        __block size_t bufferOffset = 0;

        memcpy(buffer + bufferOffset, &stack->loadAddress, sizeof(uintptr_t));
        bufferOffset += sizeof(uintptr_t);

        memcpy(buffer + bufferOffset, &stack->argc, sizeof(uintptr_t));
        bufferOffset += sizeof(uintptr_t);

        sStackIterateLists(stack, ^(StackList *list) {
            sListIterateStrings(list, ^(StackString *string) {
                memcpy(buffer + bufferOffset, &string->address, sizeof(uintptr_t));
                bufferOffset += sizeof(uintptr_t);
            });

            bufferOffset += sizeof(uintptr_t);
        });
    }

    kern_return_t err = vm_write(task, sp, (vm_offset_t)buffer, (mach_msg_type_number_t)(bufferLength));

    if (err != KERN_SUCCESS) {
        LogError("vm_write() failed, error = %ld", (long)err);
        free(buffer);
        return false;
    }
    
    LogInfo("New memory from sp to end of region:");
    sLogHexDump(sp, buffer, bufferLength);

    free(buffer);

    *outSp = sp;

    return true;
}


#pragma mark - Public Functions

void SetLogger(os_log_t logger)
{
    sLogger = logger;
}


boolean_t InjectIntoProcess(
    pid_t       pid,
    const char *dyldLibraryPath,
    const char *dyldFrameworkPath,
    const char *dyldInsertLibraries
)
{
    boolean_t ok = true;

	task_port_t task;
	thread_act_array_t threads = NULL;
	mach_msg_type_number_t threadCount = 0;

	arm_thread_state64_t state;
	thread_state_flavor_t flavor = ARM_THREAD_STATE64;
    mach_msg_type_number_t stateCount = ARM_THREAD_STATE64_COUNT;

    #define Check(__CONDITION__, __FORMAT__, ...) \
        if (!(__CONDITION__)) { LogError(__FORMAT__, __VA_ARGS__); ok = false; goto cleanup; }

    // Get task via task_for_pid()
    {
        kern_return_t err = task_for_pid(mach_task_self(), pid, &task);
        Check(err == KERN_SUCCESS, "task_for_pid() failed, error = %ld", (long)err);
    }

    // Get threads/threadCount via task_threads()
    {
        kern_return_t err = task_threads(task, &threads, &threadCount);
        Check(err == KERN_SUCCESS, "task_threads() failed, error = %ld", (long)err);
        Check(threadCount == 1, "threadCount is %ld, expected 1", (long)threadCount);
    }

    // Fill state/stateCount via thread_get_state()
    {
        kern_return_t err = thread_get_state(threads[0], flavor, (thread_state_t)&state, &stateCount);
        Check(err == KERN_SUCCESS, "thread_get_state() failed, error = %ld", (long)err);
    }

    // Convert state/stateCount via thread_convert_thread_state()
    {
        kern_return_t err = thread_convert_thread_state(
            threads[0], THREAD_CONVERT_THREAD_STATE_TO_SELF, flavor,
            (thread_state_t)&state,  stateCount,
            (thread_state_t)&state, &stateCount
        );
        
        sLogThreadState(&state);
        
        Check(err == KERN_SUCCESS, "thread_convert_thread_state() failed, error = %ld", (long)err);
    }
   
    uintptr_t pc = arm_thread_state64_get_pc(state);
    uintptr_t sp = arm_thread_state64_get_sp(state);
    uintptr_t modifiedSp = 0;
    
    Stack *stack = NULL;

    LogInfo("Checking _dyld_start() at %p\n", pc);
    ok = ok && sCheckDyldStart(task, pc);

    LogInfo("Patching amfi_check_dyld_policy_self()\n");
    vm_address_t my_amfi_check_dyld_policy_self = 0;
    ok = ok && sFindAMFICheckPolicy(task, pc, &my_amfi_check_dyld_policy_self);
	ok = ok && sWriteAMFICheckPolicyPatch(task, my_amfi_check_dyld_policy_self);

    LogInfo("Reading stack\n");
    ok = ok && sReadStack(task, sp, &stack);

    LogInfo("Modifying stack\n");
    ok = ok && sModifyStack(task, stack, dyldLibraryPath, dyldFrameworkPath, dyldInsertLibraries);

    LogInfo("Writing new stack\n");
    ok = ok && sWriteStack(task, stack, &modifiedSp);

    LogInfo("Patching _dyld_start()\n");
    ok = ok && sWriteDyldStartPatch(task, pc, sp - modifiedSp);

    sFreeStack(stack);

cleanup:
    if (threads && threadCount > 0) {
        for (size_t i = 0; i < threadCount; i++) {
            kern_return_t err = mach_port_deallocate(mach_task_self(), threads[i]);

            if (err != KERN_SUCCESS) {
                LogError("mach_port_deallocate(...threads[%ld]) failed, error = %ld", (long)i, (long)err);
            }
        }

        {
            kern_return_t err = vm_deallocate(mach_task_self(), (vm_address_t)threads, sizeof(*threads));
            if (err != KERN_SUCCESS) {
                LogError("vm_deallocate() failed, error = %ld", (long)err);
            }
        }
    }

    return ok;
}

