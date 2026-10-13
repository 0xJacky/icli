#import "IcliPrivate.h"
#import "IcliJSON.h"
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <dlfcn.h>
#import <errno.h>
#import <stdlib.h>
#import <string.h>
#import <sys/sysctl.h>

// libSystem exports it; the SDK ships no libproc.h.
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

// Whether a RunningBoard identity is an application rather than one of its
// extensions or XPC services. False when this RunningBoard cannot say.
static bool icli_identity_is_application(id identity) {
    SEL selector = NSSelectorFromString(@"isApplication");
    return [identity respondsToSelector:selector] && ((BOOL (*)(id, SEL))objc_msgSend)(identity, selector);
}

char *icli_runningboard_apps_json(void) {
    @autoreleasepool {
        void *framework = dlopen(
            "/System/Library/PrivateFrameworks/RunningBoardServices.framework/RunningBoardServices",
            RTLD_NOW
        );
        Class identifierClass = NSClassFromString(@"RBSProcessIdentifier");
        Class handleClass = NSClassFromString(@"RBSProcessHandle");
        SEL identifierSelector = NSSelectorFromString(@"identifierWithPid:");
        SEL handleSelector = NSSelectorFromString(@"handleForIdentifier:error:");
        if (!framework || ![identifierClass respondsToSelector:identifierSelector] ||
            ![handleClass respondsToSelector:handleSelector]) {
            return icli_json_or_empty(@{@"error": @"RunningBoard process handles unavailable"});
        }

        int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
        size_t length = 0;
        if (sysctl(mib, 3, NULL, &length, NULL, 0) != 0) {
            return icli_json_or_empty(@{@"error": @(strerror(errno))});
        }
        length += 64 * sizeof(struct kinfo_proc);
        struct kinfo_proc *processes = calloc(1, length);
        if (!processes || sysctl(mib, 3, processes, &length, NULL, 0) != 0) {
            int error = errno;
            free(processes);
            return icli_json_or_empty(@{@"error": processes ? @(strerror(error)) : @"process allocation failed"});
        }

        NSMutableArray *apps = [NSMutableArray array];
        for (size_t i = 0; i < length / sizeof(struct kinfo_proc); i++) {
            pid_t pid = processes[i].kp_proc.p_pid;
            char path[4096] = {0};
            if (pid <= 0) continue;
            // An app whose bundle was replaced while it ran, as dpkg does on an
            // upgrade, has no path any more; RunningBoard still knows it, so
            // its identity decides below.
            bool pathless = proc_pidpath(pid, path, sizeof(path)) <= 0;
            // Exclude helpers and extensions nested inside an application bundle.
            char *app = pathless ? NULL : strstr(path, ".app/");
            if (!pathless && (!app || strchr(app + 5, '/'))) continue;
            @try {
                id identifier = ((id (*)(id, SEL, int))objc_msgSend)(identifierClass, identifierSelector, pid);
                id handle = ((id (*)(id, SEL, id, NSError **))objc_msgSend)(
                    handleClass,
                    handleSelector,
                    identifier,
                    NULL
                );
                id state = [handle valueForKey:@"currentState"];
                if (![state respondsToSelector:@selector(isRunning)] ||
                    !((BOOL (*)(id, SEL))objc_msgSend)(state, @selector(isRunning))) continue;
                id identity = [handle valueForKey:@"identity"];
                if (pathless && !icli_identity_is_application(identity)) continue;
                NSString *bundleID = [identity valueForKey:@"embeddedApplicationIdentifier"];
                if (![bundleID isKindOfClass:NSString.class] || !bundleID.length) continue;
                [apps addObject:@{@"bundle_id": bundleID, @"pid": @(pid), @"executable": @(path)}];
            } @catch (NSException *exception) {
                (void)exception;
            }
        }
        free(processes);
        return icli_json_or_empty(@{@"apps": apps});
    }
}
