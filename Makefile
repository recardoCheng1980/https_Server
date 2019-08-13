all: uhttpd

clean:
	-rm ./*.o uhttpd

uhttpd: common.c http_parser.c curlthread.c simplehttpd.c
	$(CC) -o uhttpd common.c http_parser.c curlthread.c simplehttpd.c -lcurl -lpthread -lcrypto -lssl   
