PROG=${OUTPUT}
SRCS=main.c inotify.c util.c
CFLAGS+=-DDEBUG -g
NO_MAN=1

.include <bsd.prog.mk>
