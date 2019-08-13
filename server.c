#include "common.h"
#include "server.h"

void load_dh_params(SSL_CTX *ctx,char *file) {
    DH *ret=0;
    BIO *bio;

    if ((bio=BIO_new_file(file,"r")) == NULL) berr_exit("Couldn't open DH file");

    ret=PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (SSL_CTX_set_tmp_dh(ctx,ret)<0) berr_exit("Couldn't set DH parameters");
}

void generate_eph_rsa_key(SSL_CTX *ctx) {
    RSA *rsa;

    rsa=RSA_generate_key(512,RSA_F4,NULL,NULL);

    if (!SSL_CTX_set_tmp_rsa(ctx,rsa)) berr_exit("Couldn't set RSA key");

    RSA_free(rsa);
}
