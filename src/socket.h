#ifndef _SOCKET_H_
#define _SOCKET_H_

#include "common.h"
// only TCP sockets for now
class Socket
{
    public:
        int         sock;
        std::string hostname;
        int         port;
        bool        server;
        Socket(int sockfd, std::string ip, int port);
        Socket(std::string host, int port,bool server);
        ~Socket() {
            close(sock);
        }
        int bind();
        int connect();
        int listen(int maxq);
        Socket *accept();

};
#endif
