
#ifndef CCNET_NET_H
#define CCNET_NET_H

#ifdef WIN32
    #include <inttypes.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef int socklen_t;
    #define UNUSED 
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <sys/un.h>
    #include <net/if.h>
    #include <netinet/tcp.h>
#endif

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <event2/util.h>
#else
#include <evutil.h>
#endif

#ifdef WIN32
    /* #define ECONNREFUSED WSAECONNREFUSED */
    /* #define ECONNRESET   WSAECONNRESET */
    /* #define EHOSTUNREACH WSAEHOSTUNREACH */
    /* #define EINPROGRESS  WSAEINPROGRESS */
    /* #define ENOTCONN     WSAENOTCONN */
    /* #define EWOULDBLOCK  WSAEWOULDBLOCK */
    #define sockerrno WSAGetLastError( )
#else
    #include <errno.h>
    #define sockerrno errno
#endif

#ifdef WIN32
extern int inet_aton(const char *string, struct in_addr *addr);
#endif

evutil_socket_t ccnet_net_open_tcp (const struct sockaddr *sa, int nonblock);
evutil_socket_t ccnet_net_bind_tcp (int port, int nonblock);
evutil_socket_t ccnet_net_accept (evutil_socket_t b, 
                                  struct sockaddr_storage *cliaddr,
                                  socklen_t *len, int nonblock);

int ccnet_net_make_socket_blocking (evutil_socket_t fd);

/* bind to an IPv4 address, if (*port == 0) the port number will be returned */
evutil_socket_t ccnet_net_bind_v4 (const char *ipaddr, int *port);

int  ccnet_netSetTOS   ( evutil_socket_t s, int tos );

char *sock_ntop(const struct sockaddr *sa, socklen_t salen);
uint16_t sock_port (const struct sockaddr *sa);

/* return 1 if addr_str is a valid ipv4 or ipv6 address */
int is_valid_ipaddr (const char *addr_str);


/* return 0 if success, -1 if error */
int sock_pton (const char *addr_str, uint16_t port, 
               struct sockaddr_storage *sa);

evutil_socket_t udp_client (const char *host, const char *serv,
                struct sockaddr **saptr, socklen_t *lenp);

int mcast_set_loop(evutil_socket_t sockfd, int onoff);

evutil_socket_t create_multicast_sock (struct sockaddr *sasend, socklen_t salen);

#endif
