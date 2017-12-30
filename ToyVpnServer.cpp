/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>

#ifdef __linux__

// There are several ways to play with this program. Here we just give an
// example for the simplest scenario. Let us say that a Linux box has a
// public IPv4 address on eth0. Please try the following steps and adjust
// the parameters when necessary.
//
// # Enable IP forwarding
// echo 1 > /proc/sys/net/ipv4/ip_forward
//
// # Pick a range of private addresses and perform NAT over eth0.
// iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE
//
// # Create a TUN interface.
// ip tuntap add dev tun0 mode tun
//
// # Set the addresses and bring up the interface.
// ifconfig tun0 10.0.0.1 dstaddr 10.0.0.2 up
//
// # Create a server on port 8000 with shared secret "test".
// ./ToyVpnServer tun0 8000 test -m 1400 -a 10.0.0.2 32 -d 8.8.8.8 -r 0.0.0.0 0
//
// This program only handles a session at a time. To allow multiple sessions,
// multiple servers can be created on the same port, but each of them requires
// its own TUN interface. A short shell script will be sufficient. Since this
// program is designed for demonstration purpose, it performs neither strong
// authentication nor encryption. DO NOT USE IT IN PRODUCTION!

#include <net/if.h>
#include <linux/if_tun.h>

#define handle_error_en(en, msg) \
        do { errno = en; perror(msg); exit(EXIT_FAILURE); } while(0)
#define handle_error(msg) \
        do { perror(msg); exit(EXIT_FAILURE); } while(0)

static int get_interface(char *name)
{
    const int interface = open("/dev/net/tun", O_RDWR);

    ifreq ifr;
    bzero(&ifr, sizeof(ifreq));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));

    if (ioctl(interface, TUNSETIFF, &ifr) == -1)
        handle_error("Cannot get TUN interface");

    return interface;
}

#else

#error Sorry, you have to implement this part by yourself.

#endif

static int get_tunnel(char *port, char *secret)
{
    // We use an IPv6 socket to cover both IPv4 and IPv6.
    const int tunnel = socket(AF_INET6, SOCK_DGRAM, 0);
    const int on = 1, off = 0;
    setsockopt(tunnel, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
    setsockopt(tunnel, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

    // Accept packets received on any local address.
    sockaddr_in6 addr;
    bzero(&addr, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(atoi(port));

    // Call bind(2) in a loop since Linux does not have SO_REUSEPORT.
/*    while (bind(tunnel, (sockaddr *)&addr, sizeof(addr))) {
        if (errno != EADDRINUSE) {
            return -1;
        }
        usleep(100000);
    }
*/
    if (bind(tunnel, (sockaddr *) &addr, sizeof(addr)) == -1)
        handle_error("bind");

    // Receive packets till the secret matches.
    char packet[1024];
    socklen_t addrlen;
    do {
        addrlen = sizeof(addr);
        int n = recvfrom(tunnel, packet, sizeof(packet), 0,
                (sockaddr *)&addr, &addrlen);
        if (n <= 0) {
            return -1;
        }
        packet[n] = 0;
    } while (packet[0] != 0 || strcmp(secret, &packet[1]));

    // Connect to the client as we only handle one client at a time.
    connect(tunnel, (sockaddr *)&addr, addrlen);
    return tunnel;
}

static void build_parameters(char *parameters, int size, int argc, char **argv)
{
    // Well, for simplicity, we just concatenate them (almost) blindly.
    int offset = 0;
    for (int i = 4; i < argc; ++i) {
        char *parameter = argv[i];
        int length = strlen(parameter);
        char delimiter = ',';

        // If it looks like an option, prepend a space instead of a comma.
        if (length == 2 && parameter[0] == '-') {
            ++parameter;
            --length;
            delimiter = ' ';
        }

        // This is just a demo app, really.
        if (offset + length >= size) {
            puts("Parameters are too large");
            exit(1);
        }

        // Append the delimiter and the parameter.
        parameters[offset] = delimiter;
        memcpy(&parameters[offset + 1], parameter, length);
        offset += 1 + length;
    }

    // Fill the rest of the space with spaces.
    memset(&parameters[offset], ' ', size - offset);

    // Control messages always start with zero.
    parameters[0] = 0;
}

struct int_sock {
    int interface;
    int socket;
};

void *read_send(void *ptr) {
    struct int_sock *pint_sock = (struct int_sock *) ptr;
    int socket = pint_sock->socket;
    int interface = pint_sock->interface;
    char packet[32767];
    int length;

    while ((length = read(interface, packet, sizeof(packet))) > 0)
        if (send(socket, packet, length, MSG_NOSIGNAL) == -1)
            handle_error("send");
    
    if (length == 0) printf("CANNOT read tun interface.\n");
    else if (length == -1) perror("read");

    close(interface);
    close(socket);
    return NULL;
}

void *recv_write(void *ptr) {
    struct int_sock *pint_sock = (struct int_sock *) ptr;
    int socket = pint_sock->socket;
    int interface = pint_sock->interface;
    char packet[32767];
    int length;

    while ((length = recv(socket, packet, sizeof(packet), 0)) > 0)
        if (packet[0] != 0)
            if (write(interface, packet, length) == -1)
                handle_error("write");

    if (length == 0) printf("client want to terminate this connection.\n");
    else if (length == -1) perror("recv");

    close(interface);
    close(socket);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc < 5) {
        printf("Usage: %s <tunN> <port> <secret> options...\n"
               "\n"
               "Options:\n"
               "  -m <MTU> for the maximum transmission unit\n"
               "  -a <address> <prefix-length> for the private address\n"
               "  -r <address> <prefix-length> for the forwarding route\n"
               "  -d <address> for the domain name server\n"
               "  -s <domain> for the search domain\n"
               "\n"
               "Note that TUN interface needs to be configured properly\n"
               "BEFORE running this program. For more information, please\n"
               "read the comments in the source code.\n\n", argv[0]);
        exit(1);
    }

    // Parse the arguments and set the parameters.
    char parameters[1024];
    build_parameters(parameters, sizeof(parameters), argc, argv);

    // Get TUN interface.
    int interface = get_interface(argv[1]);

    // Wait for a tunnel.
    int tunnel;
    while ((tunnel = get_tunnel(argv[2], argv[3])) != -1) {
        printf("%s: Here comes a new tunnel\n", argv[1]);

        // On UN*X, there are many ways to deal with multiple file
        // descriptors, such as poll(2), select(2), epoll(7) on Linux,
        // kqueue(2) on FreeBSD, pthread(3), or even fork(2). Here we
        // mimic everything from the client, so their source code can
        // be easily compared side by side.

        // Put the tunnel into non-blocking mode.
        //fcntl(tunnel, F_SETFL, O_NONBLOCK);

        // Send the parameters several times in case of packet loss.
        for (int i = 0; i < 3; ++i)
            if (send(tunnel, parameters, sizeof(parameters), MSG_NOSIGNAL) == -1)
            handle_error("send");

        pthread_t t_id[2];
        int res;
        struct int_sock connection;
        connection.socket = tunnel;
        connection.interface = interface;
        if ((res = pthread_create(t_id, NULL, read_send, (void *) &connection)) != 0)
            handle_error_en(res, "pthread_create");
        
        if ((res = pthread_create(t_id + 1, NULL, recv_write, (void *) &connection)) != 0)
            handle_error_en(res, "pthread_create");
        
    }
    perror("Cannot create tunnels");
    exit(1);
}
