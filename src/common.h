#ifndef __common_h__
#define __common_h__
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <cstring>
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>
#include <assert.h>
#include <iostream>

#define CRYPTFREE(_func, var)                \
    if (nullptr != (var)) {                  \
        _func(var);                          \
    }

#define VALIDATE(call, jump, arg...)        \
    do {                                    \
        long __tmp = (long)(call);          \
        if (!(__tmp)) {                     \
            cout << __LINE__ << "error" << __tmp << "\n";  \
            goto jump;                      \
        }                                   \
    } while(false);

    static inline void
Crypt_Errors(int line)
{
    int ret;
    do {
        ret = ERR_get_error();
        if (ret) {
            std::cout << "Line:" << line << " " << ERR_error_string(ret, NULL) << std::endl;
        }
    } while(ret);
}

RSA *
CRYPT_Generate_RSA_Key(int bitSize);
X509 *
CRYPT_Generate_X509_CRT(std::string name, int days, RSA *rsa_key);

void CRYPT_SSL_Init();
void CRYPT_SSL_Deinit();
#endif
