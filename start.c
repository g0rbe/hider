#include "start.h"
#include "libg/iface.h"
#include "libg/pid.h"
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/stat.h>
#include <stdio.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>

void check_tor_running(void) {

    int pid;

    if ((pid = pid_of("tor")) > 0) {
        fprintf(stderr, "Tor is running with pid %d\n", pid);
        printf("Stop Tor or check if hider is running\n");
        exit(1);
    } else if (pid < 0) {
        fprintf(stderr, "Failed to check if Tor is running: %s\n", strerror(errno));
        exit(1);
    }
}

void kill_apps(void) {

    char *apps[] = {"firefox", "firefox-esr", "firefox.real", "spotify", "thunderbird", "qbittorrent", "signal-desktop"};
    int result;
    int pid;

    printf("Finding and killing apps...\n");

    for (int i = 0; i < sizeof(apps)/sizeof(apps[0]); i++) {

        if ((pid = pid_of(apps[i])) == -1) {
            fprintf(stderr, "Failed to check if %s is running", apps[i]);
            continue;
        } else if (pid == 0) {
            continue;
        }

        if ((result = kill_all(apps[i])) < 0) {
            fprintf(stderr, "Failed to kill %s\n", apps[i]);
        } else {
            printf("Successfully killed %s\n", apps[i]);
        }

        usleep(100000);
    }
}

void set_dns(void) {

    int resolvconf;
    long int ioctl_flags;

    printf("Setting DNS...\n");

    // Check if immutable flag not left
    if ((resolvconf = open("/etc/resolv.conf", O_RDWR)) == -1) {
        fprintf(stderr, "Failed to open /etc/resolv.conf: %s\n", strerror(errno));
        exit(1);
    }

    if (ioctl(resolvconf, FS_IOC_GETFLAGS, &ioctl_flags) == -1) {
        fprintf(stderr, "Failed to get inode flags of /etc/resolv.conf: %s\n", strerror(errno));
        exit(1);
    }

    if (ioctl_flags & FS_IMMUTABLE_FL) {
        printf("Immutable flag is set on /etc/resolv.conf, removing it...\n");

        ioctl_flags ^= FS_IMMUTABLE_FL;

        if (ioctl(resolvconf, FS_IOC_SETFLAGS, &ioctl_flags) != 0) {
            fprintf(stderr, "Failed to unset immutable attribute from /etc/resolv.conf: %s\n", strerror(errno));
        }
    }

    close(resolvconf);

    // Backup resolv.conf
    if (rename("/etc/resolv.conf", "/etc/resolv.conf.bak") != 0) {
        fprintf(stderr, "Failed to create backup: %s\n", strerror(errno));
        exit(1);
    }

    if ((resolvconf = open("/etc/resolv.conf", O_CREAT | O_WRONLY)) == -1) {
        fprintf(stderr, "Failed to open /etc/resolv.conf: %s\n", strerror(errno));
        exit(1);
    }

    if (write(resolvconf,  "nameserver 127.0.0.1\n", 21) != 21) {
        fprintf(stderr, "Failed to write to /etc/resolv.conf: %s\n", strerror(errno));
        exit(1);
    }

    if (fchmod(resolvconf, 00644) != 0) {
        printf("Failed to set permissions of /etc/resolv.conf: %s\n", strerror(errno));
        exit(1);
    }

    if (ioctl(resolvconf, FS_IOC_GETFLAGS, &ioctl_flags) != 0) {
        fprintf(stderr, "Failed to get inode flags: %s\n", strerror(errno));
        exit(1);
    }

    ioctl_flags |= FS_IMMUTABLE_FL;

    if (ioctl(resolvconf, FS_IOC_SETFLAGS, &ioctl_flags) != 0) {
        fprintf(stderr, "Failed to set immutable attribute to '/etc/resolv.conf': %s\n", strerror(errno));
    }

    close(resolvconf);
}

void set_privacy_extension(void) {

    int fd;

    printf("Setting IPv6 privacy extension...\n");

    char *files[2] = {"/proc/sys/net/ipv6/conf/all/use_tempaddr", "/proc/sys/net/ipv6/conf/default/use_tempaddr"};

    for (int i = 0; i < 2; i++) {

        if ((fd = open(files[i], O_WRONLY | O_TRUNC)) == -1) {
            fprintf(stderr, "Failed to open %s: %s\n", files[i], strerror(errno));
        } else {
            if (write(fd, "2\n", 2) != 2) {
                fprintf(stderr, "Failed to write '%s: %s\n", files[i], strerror(errno));
            }
            close(fd);
        }
    }
}

void save_iptables(void) {

    printf("Backup iptables rules...\n");

    if (system("/usr/sbin/iptables-save > /etc/hider/rules.ip") != 0) {
        printf("Failed to save iptables\n");
        exit(1);
    }
}

void save_ip6tables(void) {

    printf("Backup ip6tables rules...\n");

    if (system("/usr/sbin/ip6tables-save > /etc/hider/rules.ip6") != 0) {
        printf("Failed to save ip6tables\n");
        exit(1);
    }
}

void set_iptables(void) {

    char *rules[] = {
        // Flush iptables
        "/usr/sbin/iptables -F",
        "/usr/sbin/iptables -t nat -F",
        "/usr/sbin/iptables -X",
        // Set default policy
        "/usr/sbin/iptables -P INPUT DROP",
        "/usr/sbin/iptables -P OUTPUT DROP",
        "/usr/sbin/iptables -P FORWARD DROP",
        // Dont nat Tor
        "/usr/sbin/iptables -t nat -A OUTPUT -m owner --uid-owner debian-tor -j RETURN",

        // Redirect DNS
        "/usr/sbin/iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53",
        "/usr/sbin/iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53",
        "/usr/sbin/iptables -t nat -A OUTPUT -p udp -m owner --uid-owner debian-tor -m udp --dport 53 -j REDIRECT --to-ports 53",
        // Resolve .onion
        "/usr/sbin/iptables -t nat -A OUTPUT -p tcp -d 10.192.0.0/10 -j REDIRECT --to-ports 9040",
        // Allow private IPs
        "/usr/sbin/iptables -t nat -A OUTPUT -d 127.0.0.0/8 -j RETURN",
        "/usr/sbin/iptables -A OUTPUT -d 127.0.0.0/8 -j ACCEPT",
        "/usr/sbin/iptables -t nat -A OUTPUT -d 10.0.0.0/8 -j RETURN",
        "/usr/sbin/iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT",
        "/usr/sbin/iptables -t nat -A OUTPUT -d 172.16.0.0/12 -j RETURN",
        "/usr/sbin/iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT",
        "/usr/sbin/iptables -t nat -A OUTPUT -d 192.168.0.0/16 -j RETURN",
        "/usr/sbin/iptables -A OUTPUT -d 192.168.0.0/16 -j ACCEPT",
        // Redirect everything to TransPort
        "/usr/sbin/iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040",
        // Allow related + Tor output, reject others
        "/usr/sbin/iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "/usr/sbin/iptables -A OUTPUT -m owner --uid-owner debian-tor -j ACCEPT",
        "/usr/sbin/iptables -A OUTPUT -j REJECT",
        // Simple stateful firewall
        "/usr/sbin/iptables -A INPUT -i lo -j ACCEPT",
        "/usr/sbin/iptables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        "/usr/sbin/iptables -A INPUT -p tcp -j REJECT --reject-with tcp-reset",
        "/usr/sbin/iptables -A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable",
        "/usr/sbin/iptables -A INPUT -p icmp -j REJECT --reject-with icmp-port-unreachable",
        "/usr/sbin/iptables -A INPUT -j REJECT --reject-with icmp-proto-unreachable"};

    printf("Configuring iptables...\n");

    for (int i = 0; i < sizeof(rules)/sizeof(rules[0]); i++) {

        if (system(rules[i]) != 0) {
            fprintf(stderr, "Failed to set iptables rule: %s\n", rules[1]);
            exit(1);
        }
        usleep(100000);
    } 
}

void set_ip6tables(void) {

    char *rules[] = {
        // Flush iptables
        "/usr/sbin/ip6tables -F",
        "/usr/sbin/ip6tables -t nat -F",
        "/usr/sbin/ip6tables -X",
        // Set default policy
        "/usr/sbin/ip6tables -P INPUT DROP",
        "/usr/sbin/ip6tables -P OUTPUT DROP",
        "/usr/sbin/ip6tables -P FORWARD DROP",
        // Dont nat Tor
        "/usr/sbin/ip6tables -t nat -A OUTPUT -m owner --uid-owner debian-tor -j RETURN",

        // Redirect DNS
        "/usr/sbin/ip6tables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53",
        "/usr/sbin/ip6tables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53",
        "/usr/sbin/ip6tables -t nat -A OUTPUT -p udp -m owner --uid-owner debian-tor -m udp --dport 53 -j REDIRECT --to-ports 53",
        // Resolve .onion
        "/usr/sbin/ip6tables -t nat -A OUTPUT -p tcp -d fc00::/7 -j REDIRECT --to-ports 9040",
        // Allow private IPs
        "/usr/sbin/ip6tables -t nat -A OUTPUT -d ::1/128 -j RETURN",
        "/usr/sbin/ip6tables -A OUTPUT -d ::1/128 -j ACCEPT",
        
        // Redirect everything to TransPort
        "/usr/sbin/ip6tables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports 9040",
        // Allow related + Tor output, reject others
        "/usr/sbin/ip6tables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT",
        "/usr/sbin/ip6tables -A OUTPUT -m owner --uid-owner debian-tor -j ACCEPT",
        "/usr/sbin/ip6tables -A OUTPUT -j REJECT",
        // Simple stateful firewall
        "/usr/sbin/ip6tables -A INPUT -i lo -j ACCEPT",
        "/usr/sbin/ip6tables -A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        "/usr/sbin/ip6tables -A INPUT -p tcp -j REJECT --reject-with tcp-reset",
        "/usr/sbin/ip6tables -A INPUT -p udp -j REJECT",
        "/usr/sbin/ip6tables -A INPUT -p icmp -j REJECT",
        "/usr/sbin/ip6tables -A INPUT -j REJECT "};

    printf("Configuring ip6tables...\n");

    for (int i = 0; i < sizeof(rules)/sizeof(rules[0]); i++) {

        if (system(rules[i]) != 0) {
            fprintf(stderr, "Failed to set ip6tables rule: %s\n", rules[1]);
            exit(1);
        }
        usleep(100000);
    } 
    printf("ip6tables configured\n");
}

void start_tor(const char *torrc) {

    char command[256] = {0};

    printf("Starting Tor...\n");

    snprintf(command, 255, "/usr/bin/tor --hush -f %s", torrc);

    if (system(command) != 0) {
        fprintf(stderr, "Failed to start Tor\n");
        exit(1);
    }
}

void start_nm() {

    if (system("/usr/bin/systemctl -q is-active NetworkManager") > 0) {
        
        printf("Starting NetworkManager...\n");

        if (system("/usr/bin/systemctl -q start NetworkManager") != 0) {
            fprintf(stderr, "Failed to start NetworkManager\n");
        }
    } else {
        fprintf(stderr, "NetworkManager has already started!\n");
    }
}

int start_hider(char *torrc) {

    check_tor_running();

    printf("Starting... \n");

    printf("Setting interfaces down...\n");
    if (set_interfaces("down") != 0) {
        fprintf(stderr, "Failed to set interfaces\n");
    }

    kill_apps();
    
    set_dns();

    set_privacy_extension();

    save_iptables();

    save_ip6tables();

    set_iptables();

    set_ip6tables();

    start_tor(torrc);

    start_nm();

    printf("Setting interfaces up...\n");
    if (set_interfaces("up") != 0) {
        fprintf(stderr, "Failed to set interfaces down\n");
    }

    return 0;
}