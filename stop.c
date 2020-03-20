#include "stop.h"
#include "libg/pid.h"
#include "libg/iface.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

void check_tor_stopped(void) {

    int pid;

    if ((pid = pid_of("tor")) == 0) {
        fprintf(stderr, "Tor is not running!\n");
        printf("Nothing to stop...\n");
        exit(1);
    } else if (pid < 0) {
        fprintf(stderr, "Failed to check if Tor is running\n");
        exit(1);
    }
}

void restore_dns(void) {

    long int ioctl_flags;
    int fd;

    printf("Restoring DNS...\n");

    if ((fd = open("/etc/resolv.conf", O_RDONLY)) == -1) {
        fprintf(stderr, "Failed to open /etc/resolv.conf: %s\n", strerror(errno));
        exit(1);
    }

    if (ioctl(fd, FS_IOC_GETFLAGS, &ioctl_flags) != 0) {
        fprintf(stderr, "Failed to get attributes of 'resolv.conf': %s\n", strerror(errno));
        exit(1);
    }

    ioctl_flags ^= FS_IMMUTABLE_FL;

    if (ioctl(fd, FS_IOC_SETFLAGS, &ioctl_flags) != 0) {
        fprintf(stderr, "Failed to remove immutablity from resolv.conf: %s\n", strerror(errno));
        exit(1);
    }

    close(fd);

    if (rename("/etc/resolv.conf.bak", "/etc/resolv.conf") != 0) {
        fprintf(stderr, "Failed to restore DNS: %s\n", strerror(errno));
        exit(1);
    }
}

void unset_privacy_extension(void) {

    int fd;

    printf("Setting IPv6 privacy extension...\n");

    char *files[2] = {"/proc/sys/net/ipv6/conf/all/use_tempaddr", "/proc/sys/net/ipv6/conf/default/use_tempaddr"};

    for (int i = 0; i < 2; i++) {

        if ((fd = open(files[i], O_WRONLY | O_TRUNC)) == -1) {
            fprintf(stderr, "Failed to open %s: %s\n", files[i], strerror(errno));
        } else {
            if (write(fd, "0\n", 2) != 2) {
                fprintf(stderr, "Failed to write '%s: %s\n", files[i], strerror(errno));
            }
            close(fd);
        }
    }
}

void restore_iptables(void) {

    char *rules[] = {
        // Flush iptables
        "/usr/sbin/iptables -F",
        "/usr/sbin/iptables -t nat -F",
        "/usr/sbin/iptables -X",
        // Set default policy
        "/usr/sbin/iptables -P INPUT ACCEPT",
        "/usr/sbin/iptables -P OUTPUT ACCEPT",
        "/usr/sbin/iptables -P FORWARD ACCEPT"};

    printf("Restoring iptables...\n");

    for (int i = 0; i < sizeof(rules)/sizeof(rules[0]); i ++) {

        if (system(rules[i]) != 0) {
            fprintf(stderr, "Failed to flush iptables, problematic rule: %s\n", rules[i]);
        }
    }

    if (system("/usr/sbin/iptables-restore /etc/hider/rules.ip") != 0) {
        fprintf(stderr, "Failed to restore iptables\n");
    }
}

void restore_ip6tables(void) {

    char *rules[] = {
        // Flush iptables
        "/usr/sbin/ip6tables -F",
        "/usr/sbin/ip6tables -t nat -F",
        "/usr/sbin/ip6tables -X",
        // Set default policy
        "/usr/sbin/ip6tables -P INPUT ACCEPT",
        "/usr/sbin/ip6tables -P OUTPUT ACCEPT",
        "/usr/sbin/ip6tables -P FORWARD ACCEPT"};

    printf("Restoring ip6tables...\n");

    for (int i = 0; i < sizeof(rules)/sizeof(rules[0]); i ++) {

        if (system(rules[i]) != 0) {
            fprintf(stderr, "Failed to flush ip6tables, problematic rule: %s\n", rules[i]);
        }
    }

    if (system("/usr/sbin/ip6tables-restore /etc/hider/rules.ip6") != 0) {
        fprintf(stderr, "Failed to restore ip6tables\n");
    }
}

void stop_tor(void) {

    printf("Stopping Tor...\n");

    pid_t pid;

    if ((pid = pid_of("tor")) < 0) {
        fprintf(stderr, "Failed to ged the PID of Tor\n");
    } else if (pid == 0) {
        fprintf(stderr, "Tor is not running\n");
    } else {
        
        if (kill(pid, 15) != 0) {
            fprintf(stderr, "Failed to stop Tor: %s\n", strerror(errno));
            exit(1);
        }
    }
}

void stop_nm(void) {

    if (system("/usr/bin/systemctl -q is-active NetworkManager") == 0) {
        printf("Stopping NetworkManager...\n");

        if (system("/usr/bin/systemctl -q stop NetworkManager") != 0) {
            fprintf(stderr, "Failed to stop NetworkManager\n");
        }
    } else {
        fprintf(stderr, "NetworkManager has already stopped!\n");
    }
}

void remove_leftover(void) {

    printf("Removing leftover files...\n");

    if (remove("/etc/hider/rules.ip") != 0) {
        fprintf(stderr, "Failed to remove iptables backup: %s\n", strerror(errno));
    }

    if (remove("/etc/hider/rules.ip6") != 0) {
        fprintf(stderr, "Failed to remove ip6tables backup: %s\n", strerror(errno));
    }

    if (remove("/etc/hider/hider.tor") != 0) {
        fprintf(stderr, "Failed to remove Tor log: %s\n", strerror(errno));
    }
}

int stop_hider(void) {

    check_tor_stopped();

    printf("       Stopping... \n");

    printf("Setting interfaces down...\n");
    if (set_interfaces("down") != 0) {
        fprintf(stderr, "Failed to set interfaces\n");
    }
    restore_dns();

    unset_privacy_extension();

    restore_iptables();

    restore_ip6tables();

    stop_tor();

    stop_nm();
    
    remove_leftover();

    printf("Setting interfaces up...\n");
    if (set_interfaces("up") != 0) {
        fprintf(stderr, "Failed to set interfaces\n");
    }

    return 0;
}