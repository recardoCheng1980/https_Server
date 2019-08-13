#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <time.h>
#include "http_parser.h"
#include "uthash.h"
#include "common.h"

#define array_size(x) (sizeof(x) / sizeof(x[0]))

#define MAXMSG  2048
#define MAXURLMSG  1024
#define MAXIP 20
#define MAXMAC 20
#define MAX_DEBUG_LINE 256

#define UH_LIMIT_HEADERS  128

#define UH_HTTP_MSG_GET   0
#define UH_HTTP_MSG_HEAD  1
#define UH_HTTP_MSG_POST  2

#define foreach_header(i, h) for( i = 0; (i + 1) < (sizeof(h) / sizeof(h[0])) && h[i]; i += 2 )

SSL *client_ssl[FD_SETSIZE]={0};
int ssl_finished[FD_SETSIZE]={0};
int writefd_clear[FD_SETSIZE]={0};

typedef enum {                                                                     
  INIT=0,
  ACCEPT,
  SSL_ACCEPT,                                                                       
  SSL_WANT_READ,
  SSL_WANT_WRITE,                                                                           
  DONE
} SSL_HANDSHAKE;   

typedef struct _client_struct {
  char ip[MAXIP]; //key
  char mac[MAXMAC];
  time_t ts;
  UT_hash_handle hh;         /* makes this structure hashable */
} client_struct;

typedef struct _http_request {
  int method;
  float version;
  int redirect_status;
  char *url;
  char *headers[UH_LIMIT_HEADERS];
} http_request;

typedef struct _resp_buf {
  int fd; //key
  char redirResp[MAXMSG];
  char muteResp[MAXMSG];
} resp_buf;

client_struct* client_list=NULL;
static http_request sHttpReq;
char mac[MAXMAC]= {0};
char local_req[48]= {0};
uint16_t port;
char *node_mac=NULL;
char *node_id=NULL;
char *server_url=NULL;
char *address=NULL;
FILE *fp=NULL;
uint32_t SESSION_TRACKER=0;

void log_print(char* logline)
{
  if(SESSION_TRACKER==0) {
    if (fp) {
      fclose(fp);
      fp=NULL;
    }
    system("mv /tmp/uhttpd.log /tmp/uhttpd.log.bak 2>/dev/null");
    fp=fopen ("/tmp/uhttpd.log","w+");
  }

  if (fp==NULL)
    return;

  fprintf(stdout, "%s\n", logline);
  fflush(stdout);
  //fprintf(fp ,"%s\n", logline);
  //fflush(fp);
  SESSION_TRACKER++;

  if (SESSION_TRACKER > 30000) {
    SESSION_TRACKER=0;
  }
}

char *strfind(char *haystack, int hslen, const char *needle, int ndlen)
{
  int match = 0;
  int i, j;

  for( i = 0; i < hslen; i++ ) {
    if( haystack[i] == needle[0] ) {
      match = ((ndlen == 1) || ((i + ndlen) <= hslen));

      for( j = 1; (j < ndlen) && ((i + j) < hslen); j++ ) {
        if( haystack[i+j] != needle[j] ) {
          match = 0;
          break;
        }
      }

      if( match )
        return &haystack[i];
    }
  }

  return NULL;
}

void http_bad_response(int filedes, uint32_t code, char *summary)
{
  char buffer[MAXMSG];
  int len;

  len = snprintf(buffer, sizeof(buffer),
                 "HTTP/1.1 %03i %s\r\n"
                 "Connection: close\r\n"
                 "Content-Type: text/plain\r\n\r\n"
                 "Bad request",
                 code, summary);
  send(filedes, buffer, len, 0);
}

static int do_sys_command(char* cmd)
{
  FILE *fp;

  memset(mac, 0x0, sizeof(mac));
  fp = popen(cmd, "r");
  if (fp != NULL) {
    //Read the output a line at a time - output it.
    if (fgets(mac, sizeof(mac), fp)==NULL) {
      pclose(fp);
      return 0;
    }
  } else {
    return 0;
  }
  //close
  pclose(fp);
  return 1;
}




void http_redir_response(int filedes)
{

  char buffer[MAXMSG];
  char redirect_url[MAXURLMSG];
  int len;
  char client_ip[MAXIP]= {0};
  socklen_t addr_size=sizeof(struct sockaddr_in);
  struct sockaddr_in addr;
  int res=getpeername(filedes, (struct sockaddr*)&addr, &addr_size);
  int i=0;

  strcpy(client_ip, inet_ntoa(addr.sin_addr));
  foreach_header(i, sHttpReq.headers) {
    if (!strcasecmp(sHttpReq.headers[i], "Host")) {
      char cmd[128]= {0};
      memset(cmd, 0x0, sizeof(cmd));
      snprintf(cmd, sizeof(cmd)-1, "arp -a -n %s | awk '{printf $4}'", client_ip);
      client_struct *s=NULL, *tmp = NULL;
      HASH_FIND_STR( client_list, client_ip, s);
      if (!s) {
        if (do_sys_command(cmd)) {
          if (strlen(mac)==17) {
            //add to hash table
            s = (client_struct*)malloc(sizeof(client_struct));
            strncpy(s->ip, client_ip, MAXIP);
            strncpy(s->mac, mac, MAXMAC);
            s->ts=time(NULL);
            HASH_ADD_STR( client_list, ip, s );
          }
        }
      } else {
        //check timestamp
        time_t now=time(NULL);
        if ((now - s->ts) > 600) {
          if (do_sys_command(cmd)) {
            if (strlen(mac)==17) {
              strncpy(s->mac, mac, MAXMAC);
              s->ts=now;
            }
          }
        }
        strncpy(mac, s->mac, MAXMAC);
      }

      memset(redirect_url, 0x0, sizeof(redirect_url));
      snprintf(redirect_url, sizeof(redirect_url)-1,
               "%s?node_id=%s&gateway_id=%s&node_mac=%s&client_mac=%s&client_ip=%s&ssid=%s&cont_url=http://%s%s",
               server_url, node_id, "test", node_mac, mac, client_ip, "1", sHttpReq.headers[i+1], sHttpReq.url);
      log_print(redirect_url);

      len = snprintf(buffer, sizeof(buffer),
                     "HTTP/1.1 200 OK\r\n"
                     "Connection: close\r\n"
                     "Content-Type: text/html\r\n"
                     "Pragma: no-cache\r\n"
                     "Expires: -1\r\n\r\n"
                     "<script>window.location.href='%s'</script>", redirect_url
                    );
      send(filedes, buffer, len, 0);

      if (!strcasecmp(sHttpReq.headers[i+1], local_req) && !strcasecmp(sHttpReq.url, "/dumpinfo")) {
        //dump
        log_print("===========================================================");
        char debug_line[MAX_DEBUG_LINE];
        HASH_ITER(hh, client_list, s, tmp) {
          snprintf(debug_line, sizeof(debug_line), "ip:%s, mac:%s, ts:%d", s->ip, s->mac, (uint32_t)s->ts);
          log_print(debug_line);
        }
      }
    }
  }
}

int http_header_parse(int filedes, char *buffer, int buflen)
{
  char *method  = &buffer[0];
  char *path    = NULL;
  char *version = NULL;

  char *headers = NULL;
  char *hdrname = NULL;
  char *hdrdata = NULL;

  int i;

  int hdrcount = 0;

  memset(&sHttpReq, 0, sizeof(sHttpReq));

  /* terminate initial header line */
  if( (headers = strfind(buffer, buflen, "\r\n", 2)) != NULL ) {
    buffer[buflen-1] = 0;

    *(headers++) = 0;
    *(headers++) = 0;

    /* find request path */
    if( (path = strchr(buffer, ' ')) != NULL ) {
      *(path++) = 0;
    } else {
      http_bad_response(filedes, 400, "Bad Request: URL Request Path Not Found");
      return -1;
    }

    /* find http version */
    if( (path != NULL) && ((version = strchr(path, ' ')) != NULL) ) {
      *(version++) = 0;
    } else {
      http_bad_response(filedes, 400, "Bad Request: HTTP Version Not Found");
      return -1;
    }

    /* check method */
    if( strcmp(method, "GET") && strcmp(method, "HEAD") && strcmp(method, "POST") ) {
      /* invalid method */
      http_bad_response(filedes, 405, "Method Not Allowed");
      return -1;
    } else {
      switch(method[0]) {
      case 'G':
        sHttpReq.method = UH_HTTP_MSG_GET;
        break;

      case 'H':
        sHttpReq.method = UH_HTTP_MSG_HEAD;
        break;

      case 'P':
        sHttpReq.method = UH_HTTP_MSG_POST;
        break;
      }
    }

    /* check path */
    if( !path || !strlen(path) ) {
      /* malformed request */
      http_bad_response(filedes, 400, "Bad Request");
      return -1;
    } else {
      sHttpReq.url = path;
    }

    /* check version */
    if( (version == NULL) || (strcmp(version, "HTTP/0.9") &&
                              strcmp(version, "HTTP/1.0") && strcmp(version, "HTTP/1.1")) ) {
      /* unsupported version */
      http_bad_response(filedes, 400, "Bad Request");
      return -1;
    } else {
      sHttpReq.version = strtof(&version[5], NULL);
    }

    /* process header fields */
    for( i = (int)(headers - buffer); i < buflen; i++ ) {
      /* found eol and have name + value, push out header tuple */
      if( hdrname && hdrdata && (buffer[i] == '\r' || buffer[i] == '\n') ) {
        buffer[i] = 0;

        /* store */
        if( (hdrcount + 1) < array_size(sHttpReq.headers) ) {
          sHttpReq.headers[hdrcount++] = hdrname;
          sHttpReq.headers[hdrcount++] = hdrdata;
          hdrname = hdrdata = NULL;
        }
        /* too large */
        else {
          http_bad_response(filedes, 413, "Request Entity Too Large");
          return -1;
        }
      }
      /* have name but no value and found a colon, start of value */
      else if( hdrname && !hdrdata && ((i+1) < buflen) && (buffer[i] == ':') ) {
        buffer[i] = 0;
        hdrdata = &buffer[i+1];

        //skip space after ":"
        while ((hdrdata + 1) < (buffer + buflen) && *hdrdata == ' ') {
          hdrdata++;
        }
      }
      /* have no name and found [A-Za-z], start of name */
      else if (!hdrname && isalpha(buffer[i])) {
        hdrname = &buffer[i];
      }
    }

    /* valid enough */
    sHttpReq.redirect_status = 200;
    return 0;
  }

  /* Malformed request */
  http_bad_response(filedes, 400, "Bad Request");
  return -1;
}



int make_socket (uint16_t port, char* address)
{
  int sock;
  struct sockaddr_in name;
  int reuseaddr=1;
  socklen_t reuseaddr_len;

  /* Create the socket. */
  sock = socket (PF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    perror ("socket");
    exit (EXIT_FAILURE);
  }

  /* set option */
  reuseaddr_len=sizeof(reuseaddr);
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, reuseaddr_len);

  /* Give the socket a name. */
  name.sin_family = AF_INET;
  name.sin_port = htons (port);
  name.sin_addr.s_addr = inet_addr(address);
  if (bind (sock, (struct sockaddr *) &name, sizeof (name)) < 0) {
    perror ("bind");
    exit (EXIT_FAILURE);
  }

  return sock;
}

int read_from_client (int filedes, char* buffer, int msgsize)
{
  int nbytes;

  nbytes = read (filedes, buffer, msgsize);
  if (nbytes < 0) {
    /* Read error. */
    perror ("read");
    exit (EXIT_FAILURE);
  } else if (nbytes == 0) {
    /* End-of-file. */
    return -1;
  } else {
    /* Data read. */
    return nbytes;
  }
}

int main (int argc, char **argv)
{
  int sock;
  fd_set active_readfd_set;
  fd_set active_writefd_set;
  int i;
  size_t size;
  int opt;
  SSL_CTX *ctx;


  while( (opt = getopt(argc, argv, "a:p:n:N:r:")) > 0) {
    switch (opt) {
    case 'p':
      port = atoi(optarg);
      sprintf(local_req, "127.0.0.1:%d", port);
      break;
    case 'n':
      node_mac=optarg;
      break;
    case 'r':
      server_url=optarg;
      break;
    case 'a':
      address=optarg;
      break;
    case 'N':
      node_id=optarg;
      break;
    default:
      printf("Invalid option\n\r");
      exit(1);
      break;
    }
  }

  //Sanity check
  if (address==NULL) {
    log_print("address is required");
    exit(0);
  }

  /* Build our SSL context*/                                                     
  ctx=initialize_ctx();
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL); 

  /* Create the socket and set it up to accept connections. */
  sock = make_socket (port, address);
  if (listen (sock, 64) < 0) {
    perror ("listen");
    exit (EXIT_FAILURE);
  }

  /* Initialize the set of active sockets. */
  FD_ZERO (&active_readfd_set);
  FD_SET (sock, &active_readfd_set);
  FD_ZERO (&active_writefd_set);
  FD_SET (sock, &active_writefd_set);

  while (1) {
    struct timeval tv;
    fd_set readfd_set;
    fd_set writefd_set;
    int ret;

    FD_ZERO (&readfd_set);
    FD_ZERO (&writefd_set);
    readfd_set = active_readfd_set;
    writefd_set = active_writefd_set;
    tv.tv_sec = 20;
    tv.tv_usec = 0;

    /* Block until input arrives on one or more active sockets. */
    ret=select (FD_SETSIZE, &readfd_set, &writefd_set, NULL, &tv);

    if (ret==-1) {
      log_print("select error, exit");
      sleep(1);
      exit (EXIT_FAILURE);
    }
    else if (ret==0) {
      log_print("select continue");
      continue;
    }
    else {
      //log_print("select fd");
      /* Service all the sockets with input pending. */
      for (i = 0; i < FD_SETSIZE; ++i) {
        if (FD_ISSET (i, &readfd_set)) {
          if (i == sock) {
            /* Connection request on original socket. */
            struct sockaddr_in clientname;
            int new;

            size = sizeof (clientname);
            new = accept (sock, (struct sockaddr *) &clientname, &size);
            //setFdOptions(new); 
            if (new < 0) {
              log_print("accept error, exit");
              sleep(1);
              exit (EXIT_FAILURE);
            }

            client_ssl[new] = SSL_new(ctx); 
            //sanity check if SSL_new is success
            SSL_set_bio(client_ssl[new], BIO_new(BIO_s_mem()), BIO_new(BIO_s_mem()));
            printf("New socket:%d, ssl:%p, ssl_finished:%d, write_clear:%d\n" , new, client_ssl[new], ssl_finished[new],  writefd_clear[new]);
            FD_SET (new, &active_readfd_set);
            FD_SET (new, &active_writefd_set);

            int err=SSL_accept(client_ssl[new]);
            int sslerror=SSL_get_error(client_ssl[new], err);
            if (sslerror==SSL_ERROR_WANT_READ) {
              //log_print("SSL_accept ERROR WANT READ");
              printf("SSL_accept ERROR WANT READ:%d\n", new);
            }
            else if (sslerror==SSL_ERROR_WANT_WRITE) {                             
              //log_print("SSL_accept ERROR WANT WRITE");                                     
              printf("SSL_accept ERROR WANT WRITE:%d\n", new);
            }
            else if (sslerror==SSL_ERROR_NONE) {
              //log_print("SLL_accept ERROR NONE");
              printf("SSL_accept ERROR NONE:%d\n", new);
            }   

          } else {
            char debug_line[MAX_DEBUG_LINE]={0};
            char buffer[MAXMSG]= {0};
            int read_size =recv(i, buffer, MAXMSG, MSG_NOSIGNAL);
            snprintf(debug_line, MAX_DEBUG_LINE-1, "socket:%d, read_size:%d", i, read_size);
            //log_print(debug_line);
            printf("socket:%d, read_size:%d\n", i, read_size);

            /* Data arriving on an already-connected socket. */
            if (read_size < 0) {
              //log_print("[read_size< 0] Client read error, we close client socket");
              printf("[read_size<0] Client read error, we close client socket:%d\n", i);
              close (i);
              SSL_free(client_ssl[i]);                                          
              client_ssl[i]=NULL;
              ssl_finished[i]=0;     
              writefd_clear[i]=1;
              FD_CLR (i, &active_writefd_set);
              FD_CLR (i, &active_readfd_set);
            }
            else if (read_size==0) {
              //log_print("[read_size==0] Client disconnect, we close client socket");
              printf("[read_size==0] Client disconnect, we close client socket:%d\n", i);
              close (i);
              SSL_free(client_ssl[i]);                                          
              client_ssl[i]=NULL;
              ssl_finished[i]=0;     
              writefd_clear[i]=0;
              FD_CLR (i, &active_writefd_set);
              FD_CLR (i, &active_readfd_set);
            }
            else {
#if 0
              log_print("http header parse start");
              int httpRet=http_header_parse(i, buffer, read_size);
              if (httpRet<0) {
                log_print("http header parse failure over");
                FD_CLR (i, &active_writefd_set);
                FD_CLR (i, &active_readfd_set);
                close(i);
              } else {
                log_print("http header parse success over");
                http_redir_response(i);
                FD_CLR (i, &active_writefd_set);
                FD_CLR (i, &active_readfd_set);
                close(i);
              }
              FD_CLR (i, &active_writefd_set);
              FD_CLR(i, &active_readfd_set);
#else
             //handle ssl handshake
             BIO *pInBio = SSL_get_rbio(client_ssl[i]);
             BIO_write(pInBio, buffer, read_size);
             if (ssl_finished[i]) {
               //printf("SSL_read, ssl finished, raise write select event to close fd:%d\n", i);
               char data[280]={0};
               snprintf(data, sizeof(data), "%s", "HTTP/1.1 200 OK\r\nContent-Length: 30\r\nServer: EKRServer\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n<html><body>abcd</body></html>");
               int sslWriteRet=SSL_write(client_ssl[i], data, sizeof(data));

               if (sslWriteRet<=0) { //error
                 int sslerror=SSL_get_error(client_ssl[i], sslWriteRet);
                 printf("[sslWriteRet] sslerror:%d, sslWriteRet:%d, sizeof(data):%d, socket:%d\n", sslerror, sslWriteRet, sizeof(data), i);
                 close(i);
                 SSL_free(client_ssl[i]);                                          
                 client_ssl[i]=NULL;
                 ssl_finished[i]=0;     
                 writefd_clear[i]=0;
                 FD_CLR(i, &active_readfd_set);
                 FD_CLR(i, &active_writefd_set);
                 break;
               }
               else {
                 //performIO                                                        
                 BIO *pOutBio= SSL_get_wbio(client_ssl[i]);                         
                 int bioAvailable=BIO_pending(pOutBio);                             
                 //printf("complete bioAvailable :%d\n", bioAvailable);               
                 if (bioAvailable<0) {                                              
                   //printf("complete bioAvailable failed");                          
                 }                                                                  
                 else if (bioAvailable>0){
                   char outBuffer[bioAvailable];                                 
                   int written=BIO_read(pOutBio, outBuffer, bioAvailable);       
                   //printf("complete written :%d\n", written);                    
                   int result=send(i, outBuffer, bioAvailable, MSG_NOSIGNAL);
                   //printf("complete send result:%d\n", result);                  
                   if (written==result) {
                     writefd_clear[i]=1; //set flag to let write event finished it. clear it when next wait event
                   }
 
                 }
               }

             }
             else {
               int errorCode=SSL_accept(client_ssl[i]);

               if (errorCode < 0) {                                               
                 int sslError = SSL_get_error(client_ssl[i], errorCode);             
                 if (sslError != SSL_ERROR_WANT_READ && sslError != SSL_ERROR_WANT_WRITE) {
                   //printf("SSL_read, unable to accept SSL connection: %d", sslError);
                   close(i);
                   SSL_free(client_ssl[i]);
                   client_ssl[i]=NULL;
                   ssl_finished[i]=0;     
                   writefd_clear[i]=0;
                   FD_CLR(i, &active_readfd_set);
                   FD_CLR(i, &active_writefd_set);
                   break;
                 }                                                         
               }   

               //Perform IO
               BIO *pOutBio= SSL_get_wbio(client_ssl[i]);
               int bioAvailable=BIO_pending(pOutBio);
               if (bioAvailable<0) {                                              
                 printf("bioAvailable failed:%d\n", i);
                 //log_print("bioAvailable failed");
                 close(i);
                 SSL_free(client_ssl[i]);
                 client_ssl[i]=NULL;
                 ssl_finished[i]=0;       
                 writefd_clear[i]=0;
                 FD_CLR(i, &active_writefd_set);
                 FD_CLR(i, &active_readfd_set);
               }                                                                  
               else if (bioAvailable>0){                                          
                 char outBuffer[bioAvailable];                                    
                 int written=BIO_read(pOutBio, outBuffer, bioAvailable);          
                 send(i, outBuffer, bioAvailable, MSG_NOSIGNAL);
                 ssl_finished[i]=SSL_is_init_finished(client_ssl[i]);       
               }                                                                  
             }
#endif
            }
          }
        }//read fd set

        if (FD_ISSET (i, &writefd_set)) {
          if (i==sock) {
            log_print("writefd_set error.");
            exit(1);
          }
          else {
            if (writefd_clear[i]) {
              //log_print("write event raised, close socket");
              printf("write event raised, close socket:%d\n", i);
              close(i);                                                        
              SSL_free(client_ssl[i]);
              client_ssl[i]=NULL;
              ssl_finished[i]=0;
              writefd_clear[i]=0;
              FD_CLR(i, &active_readfd_set); //remove from select list
              FD_CLR(i, &active_writefd_set); //remove from select list
            }
          }
	}//write fd set
      }//for loop
    }//select 

  }//while
}
