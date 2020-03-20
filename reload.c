#include "libg/pid.h"
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void reload_hider(const char *torrc) {

    pid_t pid;
    char command[256] = {0};

    if ((pid = pid_of("tor")) == 0) {
        fprintf(stderr, "Tor is not running!\n");
        exit(1);
    } else if (pid < 0) {
        fprintf(stderr, "Failed to check if it Tor is running: %s\n", strerror(errno));
        exit(1);
    }

    printf("Restarting Tor...\n");

    if (kill_all("tor") == 0) {
        printf("Tor killed\n");
    } else {
        fprintf(stderr, "Failed to kill Tor\n");
        exit(1);
    }

    sleep(1);

    snprintf(command, 255, "/usr/bin/tor --hush -f %s", torrc);

    if (system(command) == 0) {
        printf("Tor started!\n");
    } else {
        fprintf(stderr, "Failed to start Tor\n");
        exit(1);
    }
}