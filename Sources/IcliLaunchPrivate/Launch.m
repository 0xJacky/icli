#import "IcliLaunchPrivate.h"
#import "IcliSystemPrivate.h"
#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <notify.h>
#import <objc/message.h>
#import <stdlib.h>
#import <string.h>
#import <sys/sysctl.h>

@interface NSObject (IcliLaunchLS)
- (BOOL)openApplicationWithBundleID:(NSString *)bundleID;
@end

static mach_port_t (*pSBSSpringBoardServerPort)(void);
static void (*pSBGetScreenLockStatus)(mach_port_t, BOOL *, BOOL *);
// The Copy rule: the identifier comes back retained.
static NSString *(*pSBSCopyFrontmostApplicationDisplayIdentifier)(void) NS_RETURNS_RETAINED;
static int (*pSBSLaunchApplicationWithIdentifierAndLaunchOptions)(NSString *, NSDictionary *, NSDictionary *, BOOL);

static void icli_launch_init(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *sbs = dlopen(
            "/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices",
            RTLD_NOW
        );
        if (!sbs) return;
#define SYM(p, name) p = (typeof(p))dlsym(sbs, name)
        SYM(pSBSSpringBoardServerPort, "SBSSpringBoardServerPort");
        SYM(pSBGetScreenLockStatus, "SBGetScreenLockStatus");
        SYM(pSBSCopyFrontmostApplicationDisplayIdentifier, "SBSCopyFrontmostApplicationDisplayIdentifier");
        SYM(pSBSLaunchApplicationWithIdentifierAndLaunchOptions, "SBSLaunchApplicationWithIdentifierAndLaunchOptions");
#undef SYM
    });
}

static char *launchJSON(NSDictionary *value) {
    NSData *data = [NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
    return data ? strndup(data.bytes, data.length) : strdup("{}");
}

static bool notifyFlag(const char *name) {
    int token = 0;
    if (notify_register_check(name, &token) != NOTIFY_STATUS_OK) {
        return false;
    }
    uint64_t state = 0;
    notify_get_state(token, &state);
    notify_cancel(token);
    return state != 0;
}

// SBSGetScreenLockStatus reads unlocked on a locked iOS 26 device, and
// MobileKeyBag answers nothing useful without a passcode, so the lock comes
// from SpringBoard's notification and SBGetScreenLockStatus together.
IcliLockStatus icli_lock_status(void) {
    icli_launch_init();
    IcliLockStatus st = {
        .locked = notifyFlag("com.apple.springboard.lockstate"),
        .screen_off = notifyFlag("com.apple.springboard.hasBlankedScreen"),
    };
    if (pSBSSpringBoardServerPort && pSBGetScreenLockStatus) {
        BOOL locked = NO;
        BOOL passcode = NO;
        pSBGetScreenLockStatus(pSBSSpringBoardServerPort(), &locked, &passcode);
        st.locked = st.locked || locked;
        st.passcode_enabled = passcode;
    }
    return st;
}

// SpringBoardServices launches for a caller with
// com.apple.springboard.launchapplications. Any other caller falls back to
// LaunchServices, which needs no entitlement and answers NO while the device
// is locked; that answer is the result, not something to wait out.
IcliLaunchResult icli_launch_app(const char *bundle_id) {
    icli_launch_init();
    @autoreleasepool {
        NSString *bid = [NSString stringWithUTF8String:bundle_id];
        if (pSBSLaunchApplicationWithIdentifierAndLaunchOptions &&
            pSBSLaunchApplicationWithIdentifierAndLaunchOptions(bid, nil, nil, NO) == 0) {
            return IcliLaunchAccepted;
        }
        id ws = icli_ls_workspace();
        if ([ws respondsToSelector:@selector(openApplicationWithBundleID:)] &&
            [ws openApplicationWithBundleID:bid]) {
            return IcliLaunchAccepted;
        }
    }
    IcliLockStatus lock = icli_lock_status();
    return lock.locked || lock.screen_off ? IcliLaunchLocked : IcliLaunchRefused;
}

extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

static NSString *(*pNSStringFromRBSRole)(uint8_t);
static Class handleClass;
static Class identifierClass;
static SEL roleSelector;
static SEL identifierSelector;
static SEL handleSelector;

// Separate from icli_launch_init so icli_lock_status never loads RunningBoard.
static void icli_running_board_init(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *framework = dlopen(
            "/System/Library/PrivateFrameworks/RunningBoardServices.framework/RunningBoardServices",
            RTLD_NOW
        );
        if (framework) pNSStringFromRBSRole = dlsym(framework, "NSStringFromRBSRole");
        handleClass = NSClassFromString(@"RBSProcessHandle");
        identifierClass = NSClassFromString(@"RBSProcessIdentifier");
        roleSelector = NSSelectorFromString(@"cpuRole");
        identifierSelector = NSSelectorFromString(@"identifierWithPid:");
        handleSelector = NSSelectorFromString(@"handleForIdentifier:error:");
    });
}

// Whether the app whose executable is at `path` is tagged hidden: a view
// service SpringBoard hosts in its own interface, such as the Dock's folder
// stacks on iPad or a widget, rather than an app a user opens. Such a service
// holds the same FrontBoard focal assertion as the app on screen while it is
// shown, on the Home Screen too.
static BOOL hiddenApplication(const char *path) {
    static NSMutableDictionary<NSString *, NSNumber *> *cache;
    const char *app = path ? strstr(path, ".app/") : NULL;
    if (!app) return NO;
    NSString *bundle = [[NSString alloc] initWithBytes:path length:(NSUInteger)(app + 4 - path) encoding:NSUTF8StringEncoding];
    if (!bundle) return NO;
    @synchronized([NSProcessInfo class]) {
        if (!cache) cache = [NSMutableDictionary dictionary];
        NSNumber *hidden = cache[bundle];
        if (!hidden) {
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[bundle stringByAppendingPathComponent:@"Info.plist"]];
            id tags = info[@"SBAppTags"];
            hidden = @([tags isKindOfClass:[NSArray class]] && [tags containsObject:@"hidden"]);
            cache[bundle] = hidden;
        }
        return hidden.boolValue;
    }
}

// The FrontBoard focal assertion identifies the app receiving input. The
// older SpringBoard query may be stale even while another app is on screen.
// Hidden view services hold that assertion too and are left out. When several
// apps hold it, as with windows side by side on iPad in iOS 27, the one
// FrontBoard also gives the ForegroundFocal jetsam priority has the focus.
// Setup Assistant drops its launch assertion and never takes a workspace focal
// one, yet RunningBoard keeps its role at UserInteractiveFocal, so the role
// decides when no assertion does.
static NSString *runningBoardFocalApplication(void) {
    icli_running_board_init();
    if (![identifierClass respondsToSelector:identifierSelector] || ![handleClass respondsToSelector:handleSelector]) {
        return nil;
    }
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
    size_t length = 0;
    if (sysctl(mib, 3, NULL, &length, NULL, 0) != 0) {
        return nil;
    }
    length += 64 * sizeof(struct kinfo_proc);
    struct kinfo_proc *processes = calloc(1, length);
    if (!processes || sysctl(mib, 3, processes, &length, NULL, 0) != 0) {
        free(processes);
        return nil;
    }
    NSMutableSet<NSString *> *focalIDs = [NSMutableSet set];
    NSMutableSet<NSString *> *foregroundFocalIDs = [NSMutableSet set];
    NSMutableSet<NSString *> *hiddenFocalIDs = [NSMutableSet set];
    NSMutableSet<NSString *> *focalRoleIDs = [NSMutableSet set];
    for (size_t i = 0; i < length / sizeof(struct kinfo_proc); i++) {
        pid_t pid = processes[i].kp_proc.p_pid;
        char path[4096] = {0};
        if (pid <= 0) continue;
        // An app whose bundle was replaced while it ran has no path any more;
        // its RunningBoard identity decides below.
        bool pathless = proc_pidpath(pid, path, sizeof(path)) <= 0;
        // Only app bundles can be the frontmost application.
        char *app = pathless ? NULL : strstr(path, ".app/");
        if (!pathless && (!app || strchr(app + 5, '/') || strstr(path, "WidgetRenderer"))) continue;
        // Callers poll this, launchApp ten times a second, and a host thread
        // may have no pool of its own to drain the RunningBoard objects.
        @autoreleasepool {
        @try {
            id identifier = ((id (*)(id, SEL, int))objc_msgSend)(identifierClass, identifierSelector, pid);
            id handle = ((id (*)(id, SEL, id, NSError **))objc_msgSend)(handleClass, handleSelector, identifier, NULL);
            id identity = [handle valueForKey:@"identity"];
            SEL isApplication = NSSelectorFromString(@"isApplication");
            if (pathless && !([identity respondsToSelector:isApplication] &&
                              ((BOOL (*)(id, SEL))objc_msgSend)(identity, isApplication))) {
                continue;
            }
            NSString *bundleID = [identity valueForKey:@"embeddedApplicationIdentifier"];
            if (![bundleID isKindOfClass:[NSString class]] || !bundleID.length ||
                [bundleID containsString:@"WidgetRenderer"]) {
                continue;
            }
            id state = [handle valueForKey:@"currentState"];
            if (pNSStringFromRBSRole && [state respondsToSelector:roleSelector]) {
                uint8_t role = ((uint8_t (*)(id, SEL))objc_msgSend)(state, roleSelector);
                if ([pNSStringFromRBSRole(role) isEqualToString:@"UserInteractiveFocal"]) {
                    [focalRoleIDs addObject:bundleID];
                }
            }
            BOOL focal = NO, foregroundFocal = NO;
            for (id assertion in [state valueForKey:@"assertions"]) {
                NSString *domain = [assertion valueForKey:@"domain"];
                if ([domain isKindOfClass:[NSString class]] &&
                    ([domain containsString:@"Workspace-ForegroundFocal"] ||
                     [domain containsString:@"com.apple.frontboard:SuspendableRole-UIFocal"])) {
                    focal = YES;
                    foregroundFocal = foregroundFocal || [domain containsString:@"JetsamPriority-ForegroundFocal"];
                }
            }
            if (focal && !pathless && hiddenApplication(path)) {
                [hiddenFocalIDs addObject:bundleID];
            } else if (focal) {
                [focalIDs addObject:bundleID];
                if (foregroundFocal) [foregroundFocalIDs addObject:bundleID];
            }
        } @catch (NSException *) {
        }
        }
    }
    free(processes);
    if (focalIDs.count == 1) return focalIDs.anyObject;
    if (focalIDs.count > 1) return foregroundFocalIDs.count == 1 ? foregroundFocalIDs.anyObject : nil;
    [focalRoleIDs minusSet:hiddenFocalIDs];
    return focalRoleIDs.count == 1 ? focalRoleIDs.anyObject : nil;
}

char *icli_frontmost_app_json(void) {
    icli_launch_init();
    NSString *bid = runningBoardFocalApplication();
    if (bid.length) return launchJSON(@{@"bundle_id": bid, @"verified": @YES, @"source": @"runningboard"});
    if (pSBSCopyFrontmostApplicationDisplayIdentifier)
        bid = pSBSCopyFrontmostApplicationDisplayIdentifier();
    return launchJSON(@{
        @"bundle_id": bid.length ? bid : @"com.apple.springboard",
        @"verified": @NO,
        @"source": bid.length ? @"springboard_query" : @"unavailable",
    });
}

