# tls1.3 Tutorial
There is a good amount of content on how SSL works. This was one I [read on medium]( https://medium.com/jspoint/a-brief-overview-of-the-tcp-ip-model-ssl-tls-https-protocols-and-ssl-certificates-d5a6269fe29e).

SSL provides many modes of verification of certificates between a client and server during the handshake. Read the details [here](https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_verify.html).

SSL_VERIFY_NONE is the most basic handshake. Here the server will not send a request to the client for its certificate. The server will send a certificate, which the client can verify.
Here, we just ignore the certificate as it is self-signed. 
In this mode of operation, the authenticity of client or server cannot be verified, but we can be assured of secure communication once the handshake is complete.


# Building the tutorial
This tutorial requires openssl-dev to be installed in the system

```
mkdir build
cd build
cmake ..
make
```

# Usage

```
tlsdemo [-c] [-s 'message to send']
    -c set to enable client mode
    -s 'send the message in quotes'
    -m mode not implemented yet
```
# To Do
 * Handle readv and writev
 * Authenticate both client and server
