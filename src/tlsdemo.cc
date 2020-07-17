#include "common.h"
#include "socket.h"
#include "ssl.h"
using namespace std;

#define PORT 28973

bool service_ssl(SSLContext &sCtx, Socket *clnt) {
    string message;

    sCtx.SetFD(clnt->sock);
    if (sCtx.Accept() <= 0) {
        ERR_print_errors_fp(stderr);
        return false;
    }
    VALIDATE(sCtx.Read(message) > 0, on_error);
    message = "echo " + message;
    VALIDATE(sCtx.Write(message) > 0, on_error);
on_error:
    delete clnt;

    return (sCtx.Clear() == 1);
}

int run_server()
{
    SSLContext sCtx(false, "server");
    Socket socket("localhost", PORT, true);
    bool flag = true;

    socket.bind();
    socket.listen(4);

    // accept connection

    do {
        Socket *clnt = socket.accept();
        if (clnt == nullptr) {
            ERR_print_errors_fp(stderr);
            break;
        } else {
            flag = service_ssl(sCtx, clnt);
        }
    } while(flag);
    return 0;
}


int run_client(string message) {
    SSLContext sCtx(true, "client");
    Socket socket("localhost", PORT, false);
    SSL *ssl  = sCtx.ssl;
    if (socket.connect() != 0) {
        return -1;
    }
    SSL_set_fd(ssl, socket.sock);
    if (sCtx.handshake() <= 0) {

        return -1;
    }
    VALIDATE(sCtx.Write(message) > 0, on_error);
    VALIDATE(sCtx.Read(message) > 0, on_error);
on_error:
    return 0;
}

typedef struct ProgOpts {
    string message;
    bool server;
    int mode;
} ProgOpts;

void ParseArgsG(ProgOpts *pargs, int argc, char *argv[])
{
    int opt;
    //default values
    pargs->server = true;
    while((opt = getopt(argc, argv, "cm:s:")) != -1)
    {
        switch(opt)
        {
            case 's':
                pargs->message = optarg;
                break;
            case 'c':
                pargs->server = false;
                break;
            case 'm':
                // only SSL_VERIFY_NONE implemented
                pargs->mode = 0;
                break;
            case ':':
                cout << "Option needs a value\n";
                break;
            case '?':
                cout << "Unknown option " << optopt << endl;
                break;
        }
    }


}

int main(int argc, char * argv[]) {
    ProgOpts pargs;

    ParseArgsG(&pargs, argc, argv);
    // set up ssl
    CRYPT_SSL_Init();
    if (pargs.server) {
        run_server();
    } else {
        run_client(pargs.message);
    }
    CRYPT_SSL_Deinit();
}
