TARGETS=demo demo-static
all: libwiiso $(TARGETS)

top=.
include $(top)/common.mak

SOURCES=demo.c
include $(SOURCES:.c=.d)
OBJECTS=$(SOURCES:.c=.o)

CFLAGS+=-Iwiiso

$(OBJECTS): $(top)/common.mak Makefile

demo: LDFLAGS+=-Lwiiso -lwiiso
demo: wiiso/libwiiso.so

demo-static: LDFLAGS+=-lssl -lcrypto
demo-static: wiiso/libwiiso.a
demo-static: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $+ $(LOADLIBES) $(LDLIBS)

clean-targets:
	$(MAKE) -C wiiso clean
	-$(RM) $(TARGETS)

clean: clean-targets


.PHONY: libwiiso

libwiiso:
	$(MAKE) -C wiiso

