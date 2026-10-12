#import "IcliPrivate.h"
#import "IcliJSON.h"
#import <Foundation/Foundation.h>

@interface NSObject (IcliLS)
- (BOOL)openSensitiveURL:(NSURL *)url withOptions:(id)options;
- (NSArray *)applicationsAvailableForOpeningURL:(NSURL *)url;
- (NSArray *)applicationsAvailableForHandlingURLScheme:(NSString *)scheme;
- (id)operationToOpenResource:(NSURL *)url usingApplication:(NSString *)bundleID userInfo:(id)userInfo;
- (BOOL)openURL:(NSURL *)url withOptions:(id)options;
@end

char *icli_app_handlers_json(const char *url_or_scheme) {
    if (!url_or_scheme) {
        return icli_json_or_empty(@{@"error": @"missing url"});
    }
    NSString *arg = [NSString stringWithUTF8String:url_or_scheme];
    id ws = icli_ls_workspace();
    NSArray *proxies = nil;
    NSString *scheme = arg;
    if ([arg containsString:@"://"]) {
        NSURL *url = [NSURL URLWithString:arg];
        scheme = url.scheme ?: arg;
        if ([ws respondsToSelector:@selector(applicationsAvailableForOpeningURL:)]) {
            proxies = [ws applicationsAvailableForOpeningURL:url];
        }
    }
    if (!proxies && [ws respondsToSelector:@selector(applicationsAvailableForHandlingURLScheme:)]) {
        proxies = [ws applicationsAvailableForHandlingURLScheme:scheme];
    }
    NSMutableArray *apps = [NSMutableArray array];
    for (id proxy in proxies) {
        [apps addObject:icli_ls_app_dictionary(proxy)];
    }
    return icli_json_or_empty(@{
        @"url": arg,
        @"scheme": scheme,
        @"apps": apps,
        @"count": @(apps.count),
    });
}

bool icli_open_url_in_app(const char *url, const char *bundle_id) {
    if (!url) {
        return false;
    }
    if (!bundle_id || !bundle_id[0]) {
        return icli_open_url(url);
    }
    NSURL *u = [NSURL URLWithString:[NSString stringWithUTF8String:url]];
    NSString *bid = [NSString stringWithUTF8String:bundle_id];
    if (!u || !bid.length) {
        return false;
    }
    id ws = icli_ls_workspace();
    if ([ws respondsToSelector:@selector(operationToOpenResource:usingApplication:userInfo:)]) {
        id op = [ws operationToOpenResource:u usingApplication:bid userInfo:nil];
        if ([op respondsToSelector:@selector(start)]) {
            [op performSelector:@selector(start)];
            return true;
        }
    }
    NSDictionary *opts = @{@"LSApplicationIdentifier": bid, @"bundleid": bid};
    if ([ws respondsToSelector:@selector(openSensitiveURL:withOptions:)]) {
        return [ws openSensitiveURL:u withOptions:opts];
    }
    if ([ws respondsToSelector:@selector(openURL:withOptions:)]) {
        return [ws openURL:u withOptions:opts];
    }
    return false;
}
