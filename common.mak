CC=ccache gcc
CFLAGS=-g -O2 -Wall

%.d: %.c
	$(SHELL) -ec '$(CC) -M $(CFLAGS) $(CPPFLAGS) $< | sed "s/$*.o/& $@/g" > $@'

.PHONY: clean

clean:
	-$(RM) *.o *.d

