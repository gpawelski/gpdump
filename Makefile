
all:
	flex -l -t gpdump-scanner.l > gpdump-scanner.c
	flex -Pdpd -l -t gpdump-scanner-dpd.l > gpdump-scanner-dpd.c
	gcc -o gpdump `pkg-config --libs --cflags glib-2.0` gpdump.c gpdump-scanner.c gpdump-scanner-dpd.c

windows: gpdump.exe

gpdump.exe:
	flex -l -t gpdump-scanner.l > gpdump-scanner.c
	flex -Pdpd -l -t gpdump-scanner-dpd.l > gpdump-scanner-dpd.c
	gcc -o gpdump -D_WIN32 -I..\include\glib-2.0 -I..\lib\glib-2.0\include gpdump.c gpdump-scanner.c gpdump-scanner-dpd.c -lws2_32 -lglib-2.0
