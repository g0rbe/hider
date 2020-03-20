#include "start.h"
#include "stop.h"
#include "status.h"
#include "help.h"
#include "reload.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv) {

    if (geteuid() != 0) {
        fprintf(stderr, "Run as root!\n");
        exit(1);
    }

    char torrc[128] = "/etc/hider/torrc";

    if (argc != 2 && argc != 3) {
        printf("Usage: %s [COMMAND] [TORRC]\n", argv[0]);
        printf("Use 'help' to show help\n");
        exit(1);
    }

    if (argc == 3) {

        if (strlen(argv[2]) > 127) {
            fprintf(stderr, "Path to torrc is too long!\n");
            fprintf(stderr, "Maximum allowed character: 127, current: %ld\n", strlen(argv[2]));
            exit(1);
        }

        if (access(argv[2], R_OK) == 0) {
            memset(torrc,  '\0', 128);
            strncpy(torrc, argv[2], 128);
        } else {
            fprintf(stderr, "Read not allowed to %s: %s\n", argv[2], strerror(errno));
            exit(1);
        }
    }

    if (strcmp(argv[1], "start") == 0) {
        start_hider(torrc);
    } else if (strcmp(argv[1], "stop") == 0) {
        stop_hider();
    } else if (strcmp(argv[1], "reload") == 0) {
        reload_hider(torrc);
    } else if (strcmp(argv[1], "restart") == 0) {
        start_hider(torrc);
        sleep(3);
        stop_hider();
    } else if (strcmp(argv[1], "status") == 0) {
        status_hider();
    }else if (strcmp(argv[1], "help") == 0) {
        show_help();
    } else {
        fprintf(stderr, "Invalid command: %s\n", argv[1]);
        printf("Use 'help' to show help\n");
        exit(1);
    }
}