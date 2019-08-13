#ifndef _curlthread_h
#define _curlthread_h

#include <pthread.h>
#include <curl/curl.h>

#ifdef __cplusplus
extern "C" {
#endif

extern pthread_mutex_t signal_mutex;
extern pthread_cond_t cond;

typedef struct _curlString {
  char* ptr;
  size_t len;
} curlString;


void init_string(curlString *s);
size_t callbackFunc(void *ptr, size_t size, size_t nmemb, curlString *s);
void* curl_entry(void* param);

#ifdef __cplusplus
}
#endif
#endif
