#import "IcliPrivate.h"
#import "IcliJSON.h"
#import "RegistrationInternal.h"
#import <Foundation/Foundation.h>

@interface NSObject (IcliLS)
+ (id)applicationProxyForIdentifier:(NSString *)identifier;
- (NSArray *)allInstalledApplications;
- (BOOL)uninstallApplication:(NSString *)bundleID withOptions:(id)options;
- (BOOL)unregisterApplication:(NSURL *)url;
+ (id)enumeratorWithOptions:(NSUInteger)options;
- (BOOL)registerContainerizedApplicationWithInfoDictionaries:(NSArray *)infos
                                               operationUUID:(NSUUID *)uuid
                                              requestContext:(id)context
                                                saveObserver:(id)observer
                                           registrationError:(NSError **)error;
@end

BOOL icli_ls_register_containerized(id workspace, NSDictionary *info, NSError **error) {
    SEL containerized = @selector(
    registerContainerizedApplicationWithInfoDictionaries:operationUUID:requestContext:saveObserver:registrationError:);
    if (!info || ![workspace respondsToSelector:containerized]) return NO;
    // The interface takes each plug-in as an info dictionary of its own,
    // after the app's, and ignores plug-ins nested under _LSBundlePlugins.
    NSMutableDictionary *app = [info mutableCopy];
    id plugIns = app[@"_LSBundlePlugins"];
    [app removeObjectForKey:@"_LSBundlePlugins"];
    NSMutableArray *infos = [NSMutableArray arrayWithObject:app];
    if ([plugIns isKindOfClass:NSDictionary.class]) {
        for (NSString *identifier in [[plugIns allKeys] sortedArrayUsingSelector:@selector(compare:)])
            [infos addObject:plugIns[identifier]];
    }
    NSError *registrationError = nil;
    [workspace registerContainerizedApplicationWithInfoDictionaries:infos
                                                      operationUUID:[NSUUID UUID]
                                                     requestContext:nil
                                                       saveObserver:nil
                                                  registrationError:&registrationError];
    if (error) *error = registrationError;
    return registrationError == nil;
}

bool icli_uninstall_app(const char *bundle_id) {
    if (!bundle_id || !bundle_id[0]) {
        return false;
    }
    id ws = icli_ls_workspace();
    if (![ws respondsToSelector:@selector(uninstallApplication:withOptions:)]) {
        return false;
    }
    return [ws uninstallApplication:[NSString stringWithUTF8String:bundle_id] withOptions:nil];
}

static NSString *normalizedAppPath(NSString *path);
static NSDictionary<NSString *, id> *registeredAppsByPath(void);
static NSString *proxyBundleID(id proxy);
static id proxyAtPath(NSString *path);

/// Unregisters the application at `path`, whose registered record is `proxy` (nil when none).
static BOOL unregisterProxy(id ws, id proxy, NSString *path) {
    if (![ws respondsToSelector:@selector(unregisterApplication:)]) return NO;
    // Keep LaunchServices' exact directory URL, including after the bundle
    // disappears. Rebuilding it from a missing path produces a file URL.
    NSURL *url = icli_ls_value(proxy, @"bundleURL");
    if (!url) url = [[NSURL fileURLWithPath:path isDirectory:YES] URLByResolvingSymlinksInPath];
    return [ws unregisterApplication:url];
}

bool icli_unregister_app(const char *path) {
    if (!path) {
        return false;
    }
    return unregisterProxy(icli_ls_workspace(), proxyAtPath(normalizedAppPath(@(path))), @(path));
}

/// Comparable form of a bundle path. LaunchServices reports resolved paths
/// (a bootstrap behind a symlinked /var/jb appears under its real location),
/// so every existing component is resolved and /private/var becomes /var.
static NSString *normalizedAppPath(NSString *path) {
    path = [NSURL fileURLWithPath:path].path.stringByStandardizingPath;
    // Foundation can leave /tmp or /var/jb unresolved when the final bundle
    // has already been removed. Resolve the longest surviving ancestor so
    // stale registrations still match LaunchServices' physical paths.
    NSString *ancestor = path;
    NSMutableArray *suffix = [NSMutableArray array];
    while (ancestor.length) {
        char *resolved = realpath(ancestor.fileSystemRepresentation, NULL);
        if (resolved) {
            path = @(resolved);
            free(resolved);
            for (NSString *component in suffix.reverseObjectEnumerator)
                path = [path stringByAppendingPathComponent:component];
            break;
        }
        NSString *parent = ancestor.stringByDeletingLastPathComponent;
        if ([parent isEqual:ancestor]) break;
        [suffix addObject:ancestor.lastPathComponent];
        ancestor = parent;
    }
    if ([path hasPrefix:@"/private/var/"]) path = [path substringFromIndex:8];
    return path;
}

/// Registered application proxies keyed by normalized bundle path.
static NSDictionary<NSString *, id> *registeredAppsByPath(void) {
    id ws = icli_ls_workspace();
    NSArray *apps = [ws respondsToSelector:@selector(allInstalledApplications)]
        ? [ws performSelector:@selector(allInstalledApplications)]
        : nil;
    if (!apps) return nil;
    NSMutableDictionary *byPath = [NSMutableDictionary dictionary];
    for (id proxy in apps) {
        NSString *path = icli_ls_string(icli_ls_value(proxy, @"bundleURL"));
        if (path) byPath[normalizedAppPath(path)] = proxy;
    }
    return byPath;
}

/// Every registered app as {bundle_id, path, type, signer}, from
/// LaunchServices' application records: iOS 14 and later enumerate them from
/// lsd's database in milliseconds, where listing the proxies costs about as
/// much as reading every app's plug-ins. Proxies where the records are not
/// available. nil when LaunchServices cannot be asked.
static NSArray<NSDictionary *> *appIndex(void) {
    id ws = icli_ls_workspace();
    NSMutableArray *index = [NSMutableArray array];
    Class recordClass = NSClassFromString(@"LSApplicationRecord");
    if ([recordClass respondsToSelector:@selector(enumeratorWithOptions:)]) {
        @try {
            for (id record in [recordClass enumeratorWithOptions:0]) {
                NSString *bundleID = icli_ls_string(icli_ls_value(record, @"bundleIdentifier"));
                NSString *path = icli_ls_string(icli_ls_value(record, @"URL"));
                if (!bundleID || !path) continue;
                NSMutableDictionary *entry = [@{@"bundle_id": bundleID, @"path": normalizedAppPath(path)} mutableCopy];
                entry[@"type"] = icli_ls_string(icli_ls_value(record, @"typeForInstallMachinery"));
                entry[@"signer"] = icli_ls_string(icli_ls_value(record, @"signerIdentity"));
                [index addObject:entry];
            }
        } @catch (NSException *exception) {
            (void)exception;
            [index removeAllObjects];
        }
        if (index.count) return index;
    }
    if (![ws respondsToSelector:@selector(allInstalledApplications)]) return nil;
    for (id proxy in [ws allInstalledApplications]) {
        NSString *bundleID = proxyBundleID(proxy);
        NSString *path = icli_ls_string(icli_ls_value(proxy, @"bundleURL"));
        if (!bundleID || !path) continue;
        NSMutableDictionary *entry = [@{@"bundle_id": bundleID, @"path": normalizedAppPath(path)} mutableCopy];
        entry[@"type"] = icli_ls_string(icli_ls_value(proxy, @"applicationType"));
        entry[@"signer"] = icli_ls_string(icli_ls_value(proxy, @"signerIdentity"));
        [index addObject:entry];
    }
    return index;
}

/// The proxy of the app registered as `bundleID` whose bundle is at the
/// normalized `path`. The identifier's proxy is asked first; every proxy is
/// listed only when that one is elsewhere, as while a moved app has a record
/// at each path.
static id proxyForIdentifierAtPath(NSString *bundleID, NSString *path) {
    icli_ls_workspace();
    Class proxyClass = NSClassFromString(@"LSApplicationProxy");
    if (bundleID && [proxyClass respondsToSelector:@selector(applicationProxyForIdentifier:)]) {
        id proxy = [proxyClass applicationProxyForIdentifier:bundleID];
        NSString *proxyPath = icli_ls_string(icli_ls_value(proxy, @"bundleURL"));
        if (proxyPath && [normalizedAppPath(proxyPath) isEqual:path]) return proxy;
    }
    return registeredAppsByPath()[path];
}

/// The proxy of the app registered at the normalized `path`, nil when none is.
static id proxyAtPath(NSString *path) {
    NSArray *index = appIndex();
    if (!index) return registeredAppsByPath()[path];
    for (NSDictionary *entry in index) {
        if ([entry[@"path"] isEqual:path]) return proxyForIdentifierAtPath(entry[@"bundle_id"], path);
    }
    return nil;
}

char *icli_app_registration_json(const char *path) {
    if (!path) return icli_json_or_empty(@{@"registered": @NO});
    if (!icli_ls_workspace()) return icli_json_or_empty(@{@"error": @"LaunchServices application list unavailable"});
    id proxy = proxyAtPath(normalizedAppPath(@(path)));
    if (!proxy) return icli_json_or_empty(@{@"registered": @NO, @"path": @(path)});
    NSMutableDictionary *result = [icli_ls_app_dictionary(proxy) mutableCopy];
    result[@"registered"] = @YES;
    NSMutableArray *plugIns = [NSMutableArray array];
    id registeredPlugIns = icli_ls_value(proxy, @"plugInKitPlugins");
    for (id plugIn in [registeredPlugIns isKindOfClass:NSArray.class] ? registeredPlugIns : @[]) {
        NSString *identifier = icli_ls_string(icli_ls_value(plugIn, @"pluginIdentifier"));
        if (identifier) [plugIns addObject:identifier];
    }
    result[@"plugins"] = [plugIns sortedArrayUsingSelector:@selector(compare:)];
    return icli_json_or_empty(result);
}

/// The part of a record that a uicache registration sets, for an app or one
/// of its plug-ins. URLs become paths, so the result is a property list.
static NSDictionary *registrationOfProxy(id proxy, NSString *bundleID) {
    NSMutableDictionary *record = [NSMutableDictionary dictionary];
    record[@"bundle_id"] = bundleID;
    NSString *path = icli_ls_string(icli_ls_value(proxy, @"bundleURL"));
    if (path) record[@"path"] = normalizedAppPath(path);
    record[@"build"] = icli_ls_string(icli_ls_value(proxy, @"bundleVersion"));
    record[@"version"] = icli_ls_string(icli_ls_value(proxy, @"shortVersionString"));
    record[@"type"] = icli_ls_string(icli_ls_value(proxy, @"applicationType"));
    record[@"signer"] = icli_ls_string(icli_ls_value(proxy, @"signerIdentity"));
    record[@"containerized"] = @([icli_ls_value(proxy, @"isContainerized") boolValue]);
    record[@"data_container"] = icli_ls_string(icli_ls_value(proxy, @"dataContainerURL"));
    record[@"settings"] = @([icli_ls_value(proxy, @"hasSettingsBundle") boolValue]);
    id environment = icli_ls_value(proxy, @"environmentVariables");
    if ([environment isKindOfClass:NSDictionary.class]) record[@"environment"] = environment;
    id groups = icli_ls_value(proxy, @"groupContainerURLs");
    if ([groups isKindOfClass:NSDictionary.class])
        record[@"groups"] = [[groups allKeys] sortedArrayUsingSelector:@selector(compare:)];
    id entitlements = icli_ls_value(proxy, @"entitlements");
    if ([entitlements isKindOfClass:NSDictionary.class]) record[@"entitlements"] = entitlements;
    return record;
}

/// An app's record with its plug-ins under "plugins".
static NSDictionary *recordOfApp(id proxy, NSString *bundleID) {
    NSMutableDictionary *record = [registrationOfProxy(proxy, bundleID) mutableCopy];
    NSMutableArray *plugIns = [NSMutableArray array];
    id registeredPlugIns = icli_ls_value(proxy, @"plugInKitPlugins");
    for (id plugIn in [registeredPlugIns isKindOfClass:NSArray.class] ? registeredPlugIns : @[]) {
        NSString *identifier = icli_ls_string(icli_ls_value(plugIn, @"pluginIdentifier"));
        if (identifier) [plugIns addObject:registrationOfProxy(plugIn, identifier)];
    }
    record[@"plugins"] = plugIns;
    return record;
}

static char *propertyListString(id object) {
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:object
                                                              format:NSPropertyListXMLFormat_v1_0
                                                             options:0
                                                               error:nil];
    return data ? strndup(data.bytes, data.length) : NULL;
}

char *icli_app_index_plist(void) {
    NSArray *index = appIndex();
    return index ? propertyListString(index) : NULL;
}

char *icli_app_record_plist(const char *bundle_id, const char *path) {
    if (!bundle_id || !path) return NULL;
    if (!icli_ls_workspace()) return NULL;
    id proxy = proxyForIdentifierAtPath(@(bundle_id), normalizedAppPath(@(path)));
    if (!proxy) return propertyListString(@{});
    return propertyListString(recordOfApp(proxy, proxyBundleID(proxy) ?: @(bundle_id)));
}

char *icli_normalized_app_path(const char *path) {
    return path ? strdup(normalizedAppPath(@(path)).fileSystemRepresentation) : NULL;
}

static NSString *proxyBundleID(id proxy) {
    return icli_ls_string(icli_ls_value(proxy, @"applicationIdentifier"))
        ?: icli_ls_string(icli_ls_value(proxy, @"bundleIdentifier"));
}

/// Whether `path` is directly inside the directory that `prefix` (ending in "/") names.
static BOOL isDirectChild(NSString *path, NSString *prefix) {
    return [path hasPrefix:prefix] && ![[path substringFromIndex:prefix.length] containsString:@"/"];
}

/// Unregisters every registered application whose bundle lives directly in `directory`.
char *icli_apps_unregister_directory_json(const char *directory) {
    if (!directory) return icli_json_or_empty(@{@"error": @"directory required"});
    NSString *root = normalizedAppPath(@(directory));
    NSString *prefix = [root stringByAppendingString:@"/"];
    NSMutableArray *unregistered = [NSMutableArray array], *failed = [NSMutableArray array];
    id ws = icli_ls_workspace();
    NSDictionary *apps = registeredAppsByPath();
    for (NSString *path in apps) {
        if (!isDirectChild(path, prefix)) continue;
        if (unregisterProxy(ws, apps[path], path))
            [unregistered addObject:path];
        else [failed addObject:path];
    }
    NSDictionary *after = registeredAppsByPath();
    NSMutableArray *remaining = [NSMutableArray array];
    for (NSString *path in unregistered) if (after[path]) [remaining addObject:path];
    return icli_json_or_empty(@{
        @"directory": root,
        @"unregistered": unregistered,
        @"failed": failed,
        @"unverified": remaining
    });
}
