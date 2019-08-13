#ifndef _curlthread_h
#define _curlthread_h

#include <curl/curl.h>
#include <pthread.h>
#include "uthash.h"
#include "utlist.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct el {
    int fd;
    struct el *next, *prev;
} el;

typedef struct mac_auth {
  char mac[20]; //key
  int authStatus;
  UT_hash_handle hh;         /* makes this structure hashable */
} mac_auth;

typedef struct curlString {
  char* ptr;
  size_t len;
} curlString;

typedef struct threadData {
  int fd;
  int count;
  int done;
} threadData;


extern pthread_mutex_t signal_mutex;
extern pthread_cond_t cond;
extern threadData tData;
extern mac_auth* macHash;

int isReqFired(char* mac);
void addFdbyMac(char* mac, int fd);
int getFdbyMac(char* mac);
void init_string(curlString *s);
size_t callbackFunc(void *ptr, size_t size, size_t nmemb, curlString *s);
void* curl_entry(void* param);

#ifdef __cplusplus
}
#endif
#endif
