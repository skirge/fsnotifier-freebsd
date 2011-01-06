PROG=fsnotifier
SRCS=main.c inotify.c util.c
CFLAGS+=-DDEBUG -g

.include <bsd.prog.mk>
