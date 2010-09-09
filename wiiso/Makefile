TARGETS=libwiiso.a libwiiso.so
all: $(TARGETS)

top=..
include $(top)/common.mak

SOURCES=$(wildcard *.c)
include $(SOURCES:.c=.d)
OBJECTS=$(SOURCES:.c=.o)
CFLAGS+=-fPIC

$(OBJECTS): $(top)/common.mak Makefile

libwiiso.a: $(OBJECTS)
	$(AR) rcs $@ $+

libwiiso.so: LDFLAGS+=-shared -lcrypto -lssl
libwiiso.so: $(OBJECTS)
	$(CC) $(CFLAGS) -o $@ $(LDFLAGS) $(LOADLIBES) $+ $(LDLIBS)


clean-targets:
	-$(RM) $(TARGETS)

clean: clean-targets
