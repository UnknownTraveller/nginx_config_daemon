#include <stdlib.h>
#include <stdio.h> // files
#include <string.h> // memory

#include <errno.h> // errno variable
#include <unistd.h> // linux system header
#include <dirent.h> // list directories
#include <utmp.h> // utmp file (logged in users)
#include <pwd.h> // getpwdnam (find uid from user name from utmp file)
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
        setuid(uid);
        
        notify_init("nginx");
        NotifyNotification* notification = notify_notification_new(caption, message, icon);
        notify_notification_show(notification, NULL);
        g_object_unref(G_OBJECT(notification));
        notify_uninit();

        exit(0);
    } else if(cpid > 0) {
        return; // nothing to do in the host anymore
    } else {
        die("fork()");
    }
}

void notify_all_users(char* caption, char* message, char* icon) {
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

    strcpy(filepath, "/var/wwww/");
    strcat(filepath, vhost);
    strcat(filepath, "/.nginx");

    if (access(filepath, F_OK) == -1 && errno == ENOENT) {
        // copy("/var/nginx/.nginx.default", filepath);
    }

    multi_watch_add(watch, filepath, IN_CLOSE_WRITE, update_config);
    free(filepath);
}

void new_virtualhost(MultiWatch* watch, struct inotify_event* event) {

    // add host to /etc/hosts file
    FILE* etc_hosts = fopen("/etc/hosts", "a");
    if (etc_hosts) {
        fputs("127.0.0.1\t\t", etc_hosts);
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

    ICHECKED(1 + 5*3, 16);

    notify_all_users("Hallo, Welt!", "Diese Nachricht wurde direkt über libnotify an alle angemeldeten grafischen Benutzer gesendet!", NOTIFY_ICON_INFORMATION);

    return 0;

    MultiWatch watch = {};
    
    //monitor default nginx config file.    
    multi_watch_add(&watch, "/etc/nginx/nginx.conf", IN_CLOSE_WRITE, update_config);

    //monitor /var/www directory
    multi_watch_add(&watch, "/var/www/", IN_CREATE, new_virtualhost);

    //monitor every config file in every directory in /var/www
    DIR* var_www = PCHECKED(opendir("/var/www/"));

    struct dirent *dirp;
    while ((dirp = readdir(var_www)) != NULL) {
        add_nginx_config(&watch, dirp->d_name);
    }

    closedir(var_www);
    


    while (1) {
        multi_watch_select(&watch);
    }
 

    return 0;
}