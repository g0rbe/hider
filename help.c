#include "help.h"
#include <stdio.h>
#include <stdlib.h>

void show_help(void) {

    printf("\nHide your computer in the LAN.\n");
    printf("\nUsage: hider [COMMAND] [TORRC]\n\n");
    printf("COMMANDS:\n");
    printf("    start      Start hider\n");
    printf("    stop       Stop hider\n");
    printf("    reload     Restart Tor only\n");
    printf("    restart    Restart hider\n");
    printf("    status      Check the status of hider\n");
    printf("    help       Show this menu\n\n");
    printf("TORRC:\n");
    printf("    Path to the torrc file.\n");
    printf("    The default value is '/etc/hider/torrc'.\n\n");
}