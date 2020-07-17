#include "ssl.h"
using namespace std;


SSLContext::SSLContext(bool client, string identifier)
{
    RSA *rsa = nullptr;
    X509 *cert = nullptr;
    name = identifier;
    if (client) {
        ctx = SSL_CTX_new(SSLv23_client_method());
    } else {
        ctx = SSL_CTX_new(SSLv23_server_method());
    }
    //forcing TLS 1.3
    VALIDATE(SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION), on_error);
    VALIDATE(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION), on_error);


    // Generating a X509 certificate on the fly
    VALIDATE((rsa = CRYPT_Generate_RSA_Key(4096)) != nullptr, on_error);
    VALIDATE((cert= CRYPT_Generate_X509_CRT("random server", 1000, rsa))!=nullptr, on_error);
    VALIDATE((SSL_CTX_set_ecdh_auto(ctx, 1)), on_error);
    VALIDATE(SSL_CTX_use_certificate(ctx, cert), on_error);
    VALIDATE(SSL_CTX_use_RSAPrivateKey(ctx, rsa), on_error);

    SSL_CTX_set_keylog_callback(ctx, callback);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    isClient = client;
    ssl = SSL_new(ctx);

on_error:
    Crypt_Errors(__LINE__);
    CRYPTFREE(RSA_free,rsa);
    CRYPTFREE(X509_free, cert);
}

    int
SSLContext::handshake()
{
    int ret;

    SSL_set_tlsext_host_name(ssl, "dontknow.u");
    SSL_set_connect_state(ssl);
    ret = SSL_do_handshake(ssl);
    if (ret <= 0) {
        ERR_print_errors_fp(stderr);
    }
    return ret;
}
    int
SSLContext::Write(std::string message)
{
    int ret = SSL_write(ssl, message.c_str(), message.length());
    if (ret <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        cout << name << " wrote " << message << endl;
    }
    return ret;
}

    int
SSLContext::Read(std::string & message)
{
    char rbuf[128];
    int ret = SSL_read(ssl, rbuf, sizeof(rbuf)-1);
    if (ret <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        rbuf[ret] = 0;
        message = rbuf;
        cout << name << " read " << message << endl;
    }
    return ret;
}

int
SSLContext::Clear() {
    int ret = SSL_clear(ssl);
    if (ret == 0) {
        Crypt_Errors(__LINE__);
    }
    return ret;
}
