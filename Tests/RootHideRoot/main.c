#include "IcliSystemPrivate.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// RootHide's root name rule and the lookup of a root on disk, checked on the
// Mac in a temporary directory.

static int failures;

static void check(int condition, const char *message) {
    if (condition) return;
    fprintf(stderr, "FAIL: %s\n", message);
    failures++;
}

static char *join(const char *parent, const char *name) {
    char *path = NULL;
    if (asprintf(&path, "%s/%s", parent, name) < 0) abort();
    return path;
}

/// Whether the lookup in `parent` answers `expected` (NULL for no root).
static int finds(const char *parent, const char *expected) {
    char *found = icli_roothide_root_in(parent);
    int same = expected ? found && strcmp(found, expected) == 0 : found == NULL;
    free(found);
    return same;
}

int main(void) {
    check(icli_roothide_root_name(".jbroot-0123456789ABCDEF"), "a name whose last byte is the XOR of the others");
    check(icli_roothide_root_name(".jbroot-000114514191980C"), "vphone's root");
    check(icli_roothide_root_name(".jbroot-fedcba9876543210"), "lower-case digits");
    check(!icli_roothide_root_name(".jbroot-0001145141919810"), "a wrong check byte");
    check(!icli_roothide_root_name(".jbroot-0123456789ABCDE"), "15 digits");
    check(!icli_roothide_root_name(".jbroot-0123456789ABCDEF0"), "17 digits");
    check(!icli_roothide_root_name(".jbroot-0x23456789ABCDEF"), "a digit that is not hexadecimal");
    check(!icli_roothide_root_name(".jbroot"), "the loader link's name");
    check(!icli_roothide_root_name("jbroot-0123456789ABCDEF"), "no leading dot");
    check(!icli_roothide_root_name(NULL), "no name");

    char parent[] = "/tmp/icli-roothide-root.XXXXXX";
    if (!mkdtemp(parent)) abort();
    char *root = join(parent, ".jbroot-0123456789ABCDEF");
    char *other = join(parent, ".jbroot-000114514191980C");
    char *unchecked = join(parent, ".jbroot-0001145141919810");
    char *container = join(parent, "5F2B1C0A-0000-4000-8000-000000000000");
    char *missing = join(parent, "missing");

    check(finds(parent, NULL), "an empty directory holds no root");
    check(finds(missing, NULL), "a missing directory holds no root");
    check(finds(NULL, NULL), "no directory holds no root");

    mkdir(container, 0755);
    mkdir(unchecked, 0755);
    check(finds(parent, NULL), "an app container and a name with a wrong check byte are not roots");

    FILE *file = fopen(root, "w");
    if (file) fclose(file);
    check(finds(parent, NULL), "a file with a root's name is not a root");
    unlink(root);

    symlink(container, root);
    check(finds(parent, NULL), "a link with a root's name is not a root");
    unlink(root);

    mkdir(root, 0755);
    check(finds(parent, root), "the one root is found");

    mkdir(other, 0755);
    check(finds(parent, NULL), "two roots are not chosen between");
    rmdir(other);
    check(finds(parent, root), "the root is found again once it is the only one");

    rmdir(root);
    rmdir(unchecked);
    rmdir(container);
    rmdir(parent);
    free(root);
    free(other);
    free(unchecked);
    free(container);
    free(missing);

    if (failures) return 1;
    printf("RootHide root: all checks passed\n");
    return 0;
}
