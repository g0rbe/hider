#include "libg/pid.h"
#include "libg/http.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json-c/json.h>

void check_tor(void) {

    pid_t pid;

    if ((pid = pid_of("tor")) > 0) {
        printf("Tor is running\n");
    } else if (pid == 0) {
        fprintf(stderr, "Tor is NOT running!\n"); 
    } else {
        fprintf(stderr, "Failed to check if Tor is running\n");
    }
}

void check_ip(void) {

    struct json_object *resp_json;
    struct json_object *ip;
    struct json_object *loc;

    char *resp = http_get("https://wtfismyip.com/json");

    if (resp == NULL) {
        fprintf(stderr, "Failed to get ip\n");
        return;
    }
    
    resp_json = json_tokener_parse(resp);

    ip = json_object_object_get(resp_json, "YourFuckingIPAddress");
    loc = json_object_object_get(resp_json, "YourFuckingLocation");

    printf("Your IP is %s (%s)\n", json_object_get_string(ip), json_object_get_string(loc));
    
    free(ip);
}

int status_hider(void) {

    check_tor();

    check_ip();

    return 0;
}