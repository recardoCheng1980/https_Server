all: uhttpd

clean:
	-rm ./*.o uhttpd

uhttpd: common.c http_parser.c simplehttpd.c
	$(CC) -o uhttpd common.c http_parser.c simplehttpd.c -lcrypto -lssl   
