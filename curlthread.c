#include <stdio.h>
#include <stdlib.h>
#include "curlthread.h"

pthread_mutex_t signal_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
threadData tData={0, 1000, 0};

void init_string(curlString *s) {
  s->len = 0;
  s->ptr = (char*) malloc(s->len+1);
  if (s->ptr == NULL) {
    fprintf(stderr, "malloc() failed\n");
    exit(EXIT_FAILURE);
  }
  s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, curlString *s)
{
  printf("pointer in writefunc:%p, thread id:%x\n", s, pthread_self());

  size_t new_len = s->len + size*nmemb;
  s->ptr = (char*) realloc(s->ptr, new_len+1);

  if (s->ptr == NULL) {
    fprintf(stderr, "realloc() failed\n");
  }
  memcpy(s->ptr+s->len, ptr, size*nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;
  printf ("%s", s->ptr);
  printf ("==============\n") ;

  return size*nmemb;
}

void* curl_entry(void* param)
{
  CURL *curl;
  CURLcode res;

  while (1) {
    printf("curl thread wait unlock...\n");

    pthread_mutex_lock( &signal_mutex );
    pthread_cond_wait(&cond, &signal_mutex);
    pthread_mutex_unlock(&signal_mutex);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if(curl) {
      curlString s;
      init_string(&s);

      //curl_easy_setopt(curl, CURLOPT_URL, "https://example.com/");
      curl_easy_setopt(curl, CURLOPT_URL, "https://35.229.214.234:1568/");
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
      curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
      res = curl_easy_perform(curl);

      if (res == CURLE_OK) {
        printf("==============\n");
        printf("%s\n", s.ptr);
        free(s.ptr);
        s.ptr=NULL;
      }   

      pthread_mutex_lock( &signal_mutex );
      tData.count++;
      tData.done=1;
      pthread_mutex_unlock(&signal_mutex);

      /* always cleanup */
      curl_easy_cleanup(curl);
    }   
    curl_global_cleanup();
  }
}
