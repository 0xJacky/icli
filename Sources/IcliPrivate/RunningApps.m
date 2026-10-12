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
            if (pid <= 0 || proc_pidpath(pid, path, sizeof(path)) <= 0) continue;
            // Exclude helpers and extensions nested inside an application bundle.
            char *app = strstr(path, ".app/");
            if (!app || strchr(app + 5, '/')) continue;
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
                NSString *bundleID = [[handle valueForKey:@"identity"] valueForKey:@"embeddedApplicationIdentifier"];
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
