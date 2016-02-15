#define _XOPEN_SOURCE 500

#include <stdlib.h>
#include <stdio.h> // files
#include <string.h> // memory

#include <errno.h> // errno variable
#include <unistd.h> // linux system header
#include <dirent.h> // list directories
#include <utmp.h> // utmp file (logged in users)
#include <pwd.h> // getpwdnam (find uid from user name from utmp file)

#include <sys/stat.h>
#include <sys/inotify.h> // watch files

#include <libnotify/notify.h> // libnotify

// icons used
#define NOTIFY_ICON_INFORMATION "dialog-information"
#define NOTIFY_ICON_ERROR "dialog-error"

// double string expansion because the preprocessor is a bitch sometimes
#define S2(x) #x
#define S(x) S2(x)

// macros to do error checking with file names and line numbers :)
#define ICHECKED(STATEMENT, ERR_VALUE) __checked(__BASE_FILE__ ":" S(__LINE__) ": " #STATEMENT, STATEMENT, ERR_VALUE)
#define PCHECKED(STATEMENT) (void*) __checked(__BASE_FILE__ ":" S(__LINE__) ": " #STATEMENT, (ssize_t)(STATEMENT), 0)

// override default malloc and free to have some more error checking
#define free(PTR) (free(PTR), PTR = 0)
#define malloc(SIZE) PCHECKED(calloc(SIZE, sizeof(char)))
#define realloc(BUF, SIZE) PCHECKED(realloc(BUF, SIZE))

void die(const char* msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

ssize_t __checked(char* statement, ssize_t result, int err_value) {
    if(result == err_value) die(statement);
    return result;
}

void notify_user(int uid, char* caption, char* message, char* icon) {
    int cpid = fork();
    if (cpid == 0) { // child
        ICHECKED(setuid(uid), -1);

        ICHECKED(notify_init("nginx"), FALSE);
        NotifyNotification* notification = PCHECKED(notify_notification_new(caption, message, icon));

        GError* showError = NULL;

        notify_notification_show(notification, &showError);

        if(showError != NULL) {
            die(showError->message);
        }

        g_object_unref(G_OBJECT(notification));
        notify_uninit();

        exit(0);
    } else if(cpid > 0) {
        printf("NOTIFY %d: %s - %s\n", uid, caption, message);
        return; // nothing to do in the host anymore
    } else {
        die("fork()");
    }
}

void notify_all_users(char* caption, char* message, char* icon) {
    printf("NOTIFY: %s - %s\n", caption, message);

    FILE* ufp = PCHECKED(fopen(_PATH_UTMP, "r"));

    struct utmp utmp_entry;

    while(fread((char*) &utmp_entry, sizeof(utmp_entry), 1, ufp) == 1) {
        // we want to have a login name, we want to be a user session and we want our line to start with ':', indicating a x11 session        
        if (*utmp_entry.ut_name && *utmp_entry.ut_line && utmp_entry.ut_type == USER_PROCESS && *utmp_entry.ut_line == ':') {
            struct passwd *user_passwd = PCHECKED(getpwnam(utmp_entry.ut_name));
            notify_user(user_passwd->pw_uid, caption, message, icon);
        }
    }

    fclose(ufp);
}

char* read_entire_file(char* path) {
    FILE* f = PCHECKED(fopen(path, "r"));
    fseek(f, 0, SEEK_END);
    
    size_t bufferLen = 0;
    size_t bufferCapacity = ftell(f) + 1;
    char* buffer = malloc(bufferCapacity);

    rewind(f);
    
    size_t bytesRead;
    while((bytesRead = fread(buffer + bufferLen, sizeof(char), bufferCapacity - bufferLen, f)) > 0) {
        bufferLen += bytesRead;
        if (bufferCapacity - bufferLen <= 1) {
            bufferCapacity += 4096;
            buffer = realloc(buffer, bufferCapacity);
        }
    }

    fclose(f);

    buffer = realloc(buffer, bufferLen + 1);
    return buffer;
}

void write_entire_file(char* path, char* contents, size_t contentLen) {
    if (contentLen == 0) {
        contentLen = strlen(contents);
    }

    FILE* f = PCHECKED(fopen(path, "w"));
    ICHECKED(fwrite(contents, sizeof(char), contentLen, f), contentLen);
    fclose(f);
}

struct SMultiWatch;
typedef struct SMultiWatch MultiWatch;
typedef void(*inotify_event_handler)(MultiWatch*, struct inotify_event*);

struct SMultiWatch {
    int inotify_handle;

    struct {
        int watch_handle;
        inotify_event_handler callback;
    } entries[FD_SETSIZE];
    unsigned int entry_count;

    fd_set watch_handles_set;
    unsigned int nfds;
};

int multi_watch_add(MultiWatch* watch, char* path, int mask, inotify_event_handler callback) {
    if (watch->inotify_handle == 0) {
        watch->inotify_handle = ICHECKED(inotify_init(), -1);

        FD_ZERO(&watch->watch_handles_set);
    }

    printf("watch directory '%s'...\n", path);

    int watchHandle = ICHECKED(inotify_add_watch(watch->inotify_handle, path, mask), -1);

    FD_SET(watchHandle, &watch->watch_handles_set);
    
    watch->entries[watch->entry_count].watch_handle = watchHandle;
    watch->entries[watch->entry_count].callback = callback;
    watch->entry_count ++;
    
    watch->nfds = (watchHandle >= watch->nfds ? watchHandle + 1 : watch->nfds);
}

void multi_watch_select(MultiWatch* watch) {
    static char buf[(sizeof(struct inotify_event) + 256) * 32] = {}; // min. 32 events
    
    int bytesRead = ICHECKED(read(watch->inotify_handle, buf, sizeof(buf)), -1);

    struct inotify_event *event = (struct inotify_event*) buf;
    while (event != NULL) {

        // find associated entry
        for(int entryIndex = 0; entryIndex < watch->entry_count; ++entryIndex) {
            if (watch->entries[entryIndex].watch_handle == event->wd) {
                if(watch->entries[entryIndex].callback != NULL) {
                    watch->entries[entryIndex].callback(watch, event);
                }
                break; // for
            }
        }

        event = (struct inotify_event*)((char*)event + sizeof(struct inotify_event) + event->len);
        if ((size_t) event >= (size_t) buf + bytesRead) {
            break; // while
        }
    }
}

void update_config(MultiWatch* watch, struct inotify_event* event) {
    if (system("nginx -t") == 0) {
        system("nginx -s reload");
        notify_all_users("nginx", "Konfiguration neu geladen", NOTIFY_ICON_INFORMATION);
    } else {
        notify_all_users("nginx", "Konfiguration ungültig", NOTIFY_ICON_ERROR);
    }
}

void add_nginx_config(MultiWatch* watch, char* vhost) {
    char* filepath = malloc(9 + strlen(vhost) + 7 + 1); // 9:/var/www/ 7:/.nginx 1:\0
    char *dirpath = malloc(9 + strlen(vhost) + 1);

    strcpy(dirpath, "/var/www/");
    strcat(dirpath, vhost);
    
    strcpy(filepath, dirpath);
    strcat(filepath, "/.nginx");

    printf("add vhost '%s', check for file '%s'\n", vhost, filepath);

    if (access(filepath, F_OK) == -1 && errno == ENOENT) {
        char* configFile = read_entire_file("/etc/nginx/.nginx.default");
        char* last_vhost_pos = configFile;
        char* next_vhost_pos;

        FILE* outputFile = PCHECKED(fopen(filepath, "w"));

        while((next_vhost_pos = strstr(last_vhost_pos, "$VHOST")) != NULL) {
            fwrite(last_vhost_pos, sizeof(char), next_vhost_pos - last_vhost_pos, outputFile);
            fwrite(vhost, sizeof(char), strlen(vhost), outputFile);
            last_vhost_pos = next_vhost_pos + 6;
        }

        fwrite(last_vhost_pos, sizeof(char), strlen(last_vhost_pos), outputFile);

        struct stat dirstats;
        stat(dirpath, &dirstats);

        fchmod(fileno(outputFile), 0775);
        fchown(fileno(outputFile), dirstats.st_uid, dirstats.st_gid);

        fclose(outputFile);
        free(configFile);
    }

    multi_watch_add(watch, filepath, IN_CLOSE_WRITE, update_config);
    free(filepath);
    free(dirpath);
}

void new_virtualhost(MultiWatch* watch, struct inotify_event* event) {

    // add host to /etc/hosts file
    FILE* etc_hosts = fopen("/etc/hosts", "a");
    if (etc_hosts) {
        fputs("127.0.0.1\t", etc_hosts);
        fputs(event->name, etc_hosts);
        fputs(".local\n", etc_hosts);
        fclose(etc_hosts);
    }

    // add .nginx file and add this file to our watch
    add_nginx_config(watch, event->name);

    char* message = malloc(21 + strlen(event->name) + 1);
    strcpy(message, "Neuer Host angelegt: ");
    strcat(message, event->name);

    notify_all_users("nginx", message, NOTIFY_ICON_INFORMATION);

    free(message);

    update_config(watch, event);
}


int main(int argc, char** argv) {

    MultiWatch watch = {};
    
    //monitor default nginx config file.    
    multi_watch_add(&watch, "/etc/nginx/nginx.conf", IN_CLOSE_WRITE, update_config);

    //monitor /var/www directory
    multi_watch_add(&watch, "/var/www/", IN_CREATE, new_virtualhost);

    //monitor every config file in every directory in /var/www
    DIR* var_www = PCHECKED(opendir("/var/www/"));

    struct dirent *dirp;
    while ((dirp = readdir(var_www)) != NULL) {
        if(strcmp(dirp->d_name, "..") != 0 && strcmp(dirp->d_name, ".") != 0) {
            add_nginx_config(&watch, dirp->d_name);
        }
    }

    closedir(var_www);
    


    while (1) {
        multi_watch_select(&watch);
    }
 

    return 0;
}