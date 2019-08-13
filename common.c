#include "common.h"
#include <arpa/inet.h>    //close                                               
#include <sys/types.h>                                                          
#include <sys/socket.h>                                                         
#include <sys/select.h>                                                         
#include <netinet/in.h>  
#include <openssl/err.h>

#define true 1                                                                  
#define false 0     

BIO *bio_err=0;
static char *pass;

static int password_cb(char *buf,int num, int rwflag,void *userdata);
static void sigpipe_handle(int x);

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

/* A simple error and exit routine*/
int err_exit(char *string) {
  fprintf(stderr,"%s\n",string);
  exit(0);
}

/* Print SSL errors and exit*/
int berr_exit(char* string) {
  BIO_printf(bio_err,"%s\n",string);
  ERR_print_errors(bio_err);
  exit(0);
}

/*The password code is not thread safe*/
static int password_cb(char *buf, int num, int rwflag, void *userdata) {
  if(num<strlen(pass)+1)
    return(0);

  strcpy(buf,pass);
  return(strlen(pass));
}

static void sigpipe_handle(int x){
  printf("sigpipe_handle\n");
}

SSL_CTX *initialize_ctx() {
    const SSL_METHOD *meth;
    SSL_CTX *ctx;

    if(!bio_err){
      /* Global system initialization*/
      SSL_library_init();
      SSL_load_error_strings();
      ERR_load_SSL_strings();
      ERR_load_CRYPTO_strings();
      ERR_load_crypto_strings();
      OpenSSL_add_all_algorithms();
      OpenSSL_add_all_ciphers();
      OpenSSL_add_all_digests();

      /* An error write context */
      bio_err=BIO_new_fp(stderr,BIO_NOCLOSE);
    }

    /* Set up a SIGPIPE handler */
    signal(SIGPIPE, sigpipe_handle);

    /* Create our context*/
    meth=SSLv23_method();
    ctx=SSL_CTX_new(meth);

    /* Load our keys and certificates*/
    if(!(SSL_CTX_use_certificate_file(ctx, "./server.crt", SSL_FILETYPE_PEM))) {
      berr_exit("Can't read certificate file");
    }

    if(!(SSL_CTX_use_PrivateKey_file(ctx, "./server.key", SSL_FILETYPE_PEM))) {
      berr_exit("Can't read key file");
    }

    return ctx;
}

void destroy_ctx(SSL_CTX *ctx) {
  SSL_CTX_free(ctx);
}


int setFdNoNagle(int fd, int isUdp) {                                      
  if (isUdp)                                                                       
    return true;                                                                   
  int32_t one = 1;                                                                 
  if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) & one, sizeof (one)) != 0) {
    return false;                                                                  
  }                                                                                
  return true;                                                                     
}                                                                                  
                                                                                   
int setFdReuseAddress(int fd) {                                                
  int32_t one = 1;                                                                 
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *) & one, sizeof (one)) != 0) {
    printf("Unable to reuse address");                                             
    return false;                                                                  
  }                                                                                
  return true;                                                                  
}                                                                               

int setFdKeepAlive(int fd, int isUdp) {                                    
  if (isUdp)                                                                    
    return true;                                                                
                                                                                
  int32_t one = 1;                                                              
  int32_t keepidle = 10;                                                        
  int32_t keepintvl = 5;                                                        
  int32_t keepcnt = 3;                                                          
                                                                                
  if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,                                  
      (const char*) & one, sizeof (one)) != 0) {                                
    printf("Unable to set SO_NOSIGPIPE");                                       
    return false;                                                               
  }                                                                             
                                                                                
  if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE,                                     
      (const char*) &keepidle, sizeof (keepidle)) != 0) {                       
    printf("Unable to set TCP_KEEPIDLE");                                       
  }                                                                             
  if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL,                                    
      (const char*) &keepintvl, sizeof (keepintvl)) != 0) {                     
    printf("Unable to set TCP_KEEPINTVL");                                      
  }                                                                             
  if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT,                                      
      (const char*) &keepcnt, sizeof (keepcnt)) != 0) {                         
    printf("Unable to set TCP_KEEPCNT");                                        
  }                                                                             
                                                                                
  return true;                                                                  
}  

int setFdNonBlock(int fd) {                                                 
  int32_t arg;                                                                  
  if ((arg = fcntl(fd, F_GETFL, NULL)) < 0) {                                   
    int32_t err = errno;                                                        
    printf("Unable to get fd flags: %d,%s", err, strerror(err));                
    return false;                                                               
  }                                                                             
  arg |= O_NONBLOCK;                                                            
  if (fcntl(fd, F_SETFL, arg) < 0) {                                            
    int32_t err = errno;                                                        
    printf("Unable to set fd flags: %d,%s", err, strerror(err));                
    return false;                                                               
  }                                                                             
                                                                                
  return true;                                                                  
} 

int setFdOptions(int fd) {                                                     
  if (!setFdNonBlock(fd)) {                                                        
    printf("Unable to set non block");                                             
    return false;                                                                  
  }                                                                                
                                                                                   
  if (!setFdKeepAlive(fd, false)) {                                                
    printf("Unable to set keep alive");                                            
    return false;                                                                  
  }                                                                                
                                                                                   
  if (!setFdNoNagle(fd, false)) {                                                  
    printf("Unable to disable Nagle algorithm");                                   
  }                                                                                
                                                                                   
  if (!setFdReuseAddress(fd)) {                                                    
    printf("Unable to enable reuse address");                                      
    return false;                                                                  
  }                                                                                
  return true;                                                                     
}   
