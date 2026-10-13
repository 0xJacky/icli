#include "IcliSystemPrivate.h"
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// RootHide keeps its bootstrap in `.jbroot-<16 hex digits>` beside the app
// bundle containers. The last byte of that number is the XOR of the seven
// before it, which tells a root from a directory that only looks like one.

bool icli_roothide_root_name(const char *name) {
    static const char prefix[] = ".jbroot-";
    if (!name || strncmp(name, prefix, sizeof(prefix) - 1) != 0) return false;
    const char *digits = name + sizeof(prefix) - 1;
    if (strlen(digits) != 16) return false;
    for (int i = 0; i < 16; i++) {
        if (!isxdigit((unsigned char)digits[i])) return false;
    }
    uint64_t value = strtoull(digits, NULL, 16);
    uint8_t check = 0;
    for (int shift = 8; shift < 64; shift += 8) check ^= (uint8_t)(value >> shift);
    return check == (uint8_t)value;
}

/// The one RootHide root directory in `parent`, or NULL when it holds none
/// or several: nothing here can say which of two is in use. A link with a
/// root's name is not a root. The caller frees the path.
char *icli_roothide_root_in(const char *parent) {
    DIR *directory = parent ? opendir(parent) : NULL;
    if (!directory) return NULL;
    char *found = NULL;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (!icli_roothide_root_name(entry->d_name)) continue;
        char *path = NULL;
        if (asprintf(&path, "%s/%s", parent, entry->d_name) < 0) continue;
        struct stat info;
        if (lstat(path, &info) != 0 || !S_ISDIR(info.st_mode) || count++ > 0) {
            free(path);
            continue;
        }
        found = path;
    }
    closedir(directory);
    if (count != 1) {
        free(found);
        return NULL;
    }
    return found;
}
