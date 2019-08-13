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

#define array_size(x) (sizeof(x) / sizeof(x[0]))

#define MAXMSG  2048
#define MAXURLMSG  1024
#define MAXIP 20
#define MAXMAC 20
#define MAX_DEBUG_LINE 128

#define UH_LIMIT_HEADERS  128

#define UH_HTTP_MSG_GET   0
#define UH_HTTP_MSG_HEAD  1
#define UH_HTTP_MSG_POST  2

#define foreach_header(i, h) for( i = 0; (i + 1) < (sizeof(h) / sizeof(h[0])) && h[i]; i += 2 )


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

  fprintf(fp ,"%s\n", logline);
  fflush(fp);
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
  int res= getpeername(filedes, (struct sockaddr*)&addr, &addr_size);
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



int
make_socket (uint16_t port, char* address)
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
  fd_set active_fd_set;
  int i;
  size_t size;
  int opt;

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

  /* Create the socket and set it up to accept connections. */
  sock = make_socket (port, address);
  if (listen (sock, 64) < 0) {
    perror ("listen");
    exit (EXIT_FAILURE);
  }


  /* Initialize the set of active sockets. */
  FD_ZERO (&active_fd_set);
  FD_SET (sock, &active_fd_set);

  while (1) {
    struct timeval tv;
    fd_set read_fd_set;
    int ret;

    tv.tv_sec = 5;
    tv.tv_usec = 0;
    read_fd_set = active_fd_set;

    /* Block until input arrives on one or more active sockets. */
    ret=select (FD_SETSIZE, &read_fd_set, NULL, NULL, &tv);

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
      log_print("select fd");
      /* Service all the sockets with input pending. */
      for (i = 0; i < FD_SETSIZE; ++i) {
        if (FD_ISSET (i, &read_fd_set)) {
          if (i == sock) {
            /* Connection request on original socket. */
            struct sockaddr_in clientname;
            int new;

            size = sizeof (clientname);
            new = accept (sock, (struct sockaddr *) &clientname, &size);
            if (new < 0) {
              log_print("accept error, exit");
              sleep(1);
              exit (EXIT_FAILURE);
            }
            FD_SET (new, &active_fd_set);
          } else {
            char buffer[MAXMSG]= {0};
            int read_size=read_from_client(i, buffer, MAXMSG);

            /* Data arriving on an already-connected socket. */
            if (read_size < 0) {
              close (i);
              FD_CLR (i, &active_fd_set);
            }
            else if (read_size==0) {
              log_print("[read_size==0] Client disconnect");
            }
            else {
              log_print("http header parse start");
              int httpRet=http_header_parse(i, buffer, read_size);

              if (httpRet<0) {
                log_print("http header parse failure over");
                FD_CLR (i, &active_fd_set);
                close(i);
              } else {
                log_print("http header parse success over");
                http_redir_response(i);
                FD_CLR (i, &active_fd_set);
                close(i);
              }
            }
          }
        }//fd set
      }//for loop
    }//select 

  }//while
}
