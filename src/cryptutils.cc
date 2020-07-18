/*
 * Wrapper functions for Crypt Openssl functions
 */
#include "common.h"

using namespace std;

    RSA *
CRYPT_Generate_RSA_Key(int bitSize)
{
    RSA *ret = nullptr, *rsa = nullptr;
    BIGNUM *bn = nullptr;
    int ret1;

    VALIDATE(bn = BN_new(), on_error);
    VALIDATE(rsa = RSA_new(), on_error);
    VALIDATE(BN_set_word(bn, RSA_F4), on_error);
    ret1 = RSA_generate_key_ex(rsa, bitSize, bn, NULL);
    VALIDATE( (ret1 != -1), on_error);
    ret = rsa;
    rsa = nullptr;
on_error:
    Crypt_Errors(__LINE__);
    CRYPTFREE(BN_free, bn);
    CRYPTFREE(RSA_free, rsa);
    return ret;
}

    X509 *
CRYPT_Generate_X509_CRT(string name, int days, RSA *rsa_key)
{
    X509 *x = 0, *ret = 0;
    X509_NAME *tmp = 0;
    EVP_PKEY *pr_key = 0;

    VALIDATE(x = X509_new(), on_error);
    VALIDATE(pr_key = EVP_PKEY_new(), on_error);
    VALIDATE(EVP_PKEY_set1_RSA(pr_key, rsa_key), on_error);

    VALIDATE(X509_set_version(x, 2), on_error); /* version 3 certificate */
    ASN1_INTEGER_set(X509_get_serialNumber(x), 0);
    VALIDATE(X509_gmtime_adj(X509_get_notBefore(x), -365), on_error);
    VALIDATE(X509_gmtime_adj(X509_get_notAfter(x), (long)days * 24 * 3600), on_error);

    VALIDATE(tmp = X509_get_subject_name(x), on_error);
    VALIDATE(X509_NAME_add_entry_by_txt(tmp, "CN", MBSTRING_ASC,
                (unsigned char*)name.c_str(), -1, -1, 0), on_error);
    VALIDATE(X509_set_subject_name(x, tmp), on_error);

    VALIDATE(X509_set_pubkey(x, pr_key), on_error);
    //setting anything less than EVP_sha256 will cause weak certificate error
    VALIDATE(X509_sign(x, pr_key, EVP_sha256()), on_error);
    ret = x;
    x = NULL;
on_error:
    Crypt_Errors(__LINE__);
    CRYPTFREE(X509_free, x);
    CRYPTFREE(EVP_PKEY_free,pr_key);
    return ret;
}


void CRYPT_SSL_Init() {
    // set up ssl
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}
void CRYPT_SSL_Deinit() {
    EVP_cleanup();
}
