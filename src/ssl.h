#ifndef _SSL_H_
#define _SSL_H_

#include "common.h"
#include "socket.h"
// Wrapper for SSL context
class SSLContext
{
    private:
        void static callback(const SSL *ctx, const char *line) {
            assert(ctx);
            std::cout << line << std::endl;
        }
        bool isClient;
        std::string name;
    public:
        SSL_CTX *ctx;
        SSL *ssl;
        SSLContext(bool client, std::string name);
        ~SSLContext() {
            CRYPTFREE(SSL_CTX_free, ctx);
            CRYPTFREE(SSL_free, ssl);
        }
        int handshake();
        int Write(std::string message);
        int Read(std::string & message);
        void SetFD(int fd) {
            SSL_set_fd(ssl, fd);
        }
        int Accept() {
            return SSL_accept(ssl);
        }
        int Clear();

};
#endif
