CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

LIBNAME = libnts

WARNING_OPTIONS=-Wall -Wextra -Wconversion -Wsign-conversion -Wsign-compare -Wpointer-arith -Wstrict-overflow=5 -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Werror=format-security -Werror=implicit-function-declaration -Wtype-limits -Wfree-nonheap-object
GCC_OPTIONS=-O2 -fPIC -fno-strict-overflow -D_GNU_SOURCE -D_FORTIFY_SOURCE=1
LIBNTS_INCLUDES=-I.

# prepend every log message the origin by defining LOGPREFIX and LOGPOSTFIX suitably
VERBOSE_LOGMESSAGE_ORIGIN= -DLOGPREFIX='"$(LIBNAME) at %s in %s line %d: "' -DLOGPOSTFIX=', __FUNCTION__, __FILE__, __LINE__'

CFLAGS += $(WARNING_OPTIONS) $(GCC_OPTIONS) $(LIBNTS_INCLUDES) $(INCLUDES) $(LINKING)

STATICLIB		= $(LIBNAME).a
LIB_SRS		= $(wildcard ./*.c)
LIB_OBJ		= $(patsubst %.c, %.o, $(LIB_SRS))
LIB_INCLUDES_DIR	= $(CURDIR) ../crypto/wolfssl/
LIB_INCLUDES	= $(addprefix -I, $(LIB_INCLUDES_DIR))
LIB_CCFLAGS		= $(CFLAGS) $(VERBOSE_LOGMESSAGE_ORIGIN)
LIB_LDFLAGS		= $(LDFLAGS) -shared

all: $(STATICLIB)

$(STATICLIB): $(LIB_OBJ)
	$(AR) rcs $@ $(LIB_OBJ)

%.o: %.c
	$(CC) $(LIB_CCFLAGS) $(LIB_INCLUDES) -c $*.c -o $*.o

.PHONY: clean
clean:
	$(RM) $(LIB_OBJ) $(STATICLIB)

