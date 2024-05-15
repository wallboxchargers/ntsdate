CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

OBJS = ntsdate.o io.o

WARNING_OPTIONS=-Wall -Wextra -Wconversion -Wsign-conversion -Wsign-compare -Wpointer-arith -Wstrict-overflow=5 -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Werror=format-security -Werror=implicit-function-declaration -Wtype-limits -Wfree-nonheap-object
GCC_OPTIONS=-O2 -fno-strict-overflow -D_FORTIFY_SOURCE=1

CFLAGS += $(WARNING_OPTIONS) $(GCC_OPTIONS) -I../libnts/ -I../crypto/wolfssl -I../libnts-netio/

#Add/link other required libraries here
LDADD += -lnts -L../libnts/ -lwolfssl -L../crypto/ -lnts-netio -L../libnts-netio/

BINARY = ntsdate

.PHONY: all
all: $(BINARY)

$(BINARY): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ ntsdate.o io.o $(LDADD)

.PHONY: clean
clean:
	rm -f $(OBJS) $(BINARY)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@
