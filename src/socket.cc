#include "socket.h"

using namespace std;

Socket::Socket(int sockfd, string ip, int port)
{
    this->port = port;
    this->hostname = ip;
    this->server = false;
    this->sock = sockfd;
}

Socket::Socket(string ip, int port, bool server)
{
    this->port = port;
    this->hostname = ip;
    this->server = server;
    this->sock = socket(AF_INET, SOCK_STREAM, 0);

}

    int
Socket::bind()
{
    struct sockaddr_in addr;
    int ret;
    int enable = 1;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (this->sock < 0) {
        return this->sock;
    }
    ret = setsockopt(this->sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int));
    if (ret < 0) {
        ERR_print_errors_fp(stderr);
        return ret;
    }
    return ::bind(this->sock, (struct sockaddr*)&addr, sizeof(addr));
}

    int
Socket::listen(int maxq)
{
    if (this->sock < 0) {
        cout << "Error bad socket \n";
        return this->sock;
    }
    return ::listen(this->sock, maxq);
}

    Socket *
Socket::accept()
{
    struct sockaddr_storage their_addr;
    socklen_t addr_size;
    char host[NI_MAXHOST];
    char strport[NI_MAXSERV];
    addr_size = sizeof their_addr;
    int newsock = ::accept(sock, (struct sockaddr *)&their_addr, &addr_size);
    if (newsock < 0) {
        cout << "Error bad socket \n";
        return nullptr;
    }
    int status = ::getnameinfo((struct sockaddr *)&their_addr, sizeof(their_addr), host, sizeof(host),
            strport, sizeof(strport), NI_NUMERICHOST|NI_NUMERICSERV);
    if (status < 0) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    } else {
        cout << "Accepted connection from " << host << ":" << port << endl;
    }
    Socket *newSocket = new Socket(newsock, host, port);
    return newSocket;
}

    int
Socket::connect()
{
    struct addrinfo *res = 0;
    int ret;
    string strport = to_string(port);

    ret = getaddrinfo(hostname.c_str(), strport.c_str(), 0, &res);
    if (ret != 0) {
        cout << "Unable to covert address :" << hostname << endl;
        return ret;
    }
    ret = ::connect(sock, (struct sockaddr *)res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (ret < 0) {
        cout << "Unable to connect to " << hostname << ":" << port << endl;
    }
    return ret;
}
