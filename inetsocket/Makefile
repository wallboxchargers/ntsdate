CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

PLUGINNAME = inetsocket

# prepend every log message the origin by defining LOGPREFIX and LOGPOSTFIX suitably
VERBOSE_LOGMESSAGE_ORIGIN= -DLOGPREFIX='"$(PLUGINNAME) at %s in %s line %d: "' -DLOGPOSTFIX=', __FUNCTION__, __FILE__, __LINE__'
WARNING_OPTIONS=-Wall -Wextra -Wconversion -Wsign-conversion -Wsign-compare -Wpointer-arith -Wstrict-overflow=5 -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Werror=format-security -Werror=implicit-function-declaration -Wtype-limits -Wfree-nonheap-object
GCC_OPTIONS=-O2 -fno-strict-overflow -D_FORTIFY_SOURCE=1

CFLAGS += $(WARNING_OPTIONS) $(GCC_OPTIONS) -I./include -I../libnts/ -I../libnts-netio/ $(VERBOSE_LOGMESSAGE_ORIGIN)

LDFLAGS += -lnts-netio -L../libnts-netio/ -lnts -L../libnts/ -lnts-log2syslog -L../libnts-log2syslog/ -lc

PLUGIN_UUID = e0bb2422-a34e-4972-9c4f-17ad2e7ee965

PLUGIN			= $(PLUGIN_UUID).plugin
PLUGIN_SRS		= $(wildcard ./*.c)
PLUGIN_OBJ		= $(patsubst %.c, %.o, $(PLUGIN_SRS))
PLUGIN_INCLUDES_DIR	= $(CURDIR) $(TEEC_EXPORT)/include

PLUGIN_INCLUDES		= $(addprefix -I, $(PLUGIN_INCLUDES_DIR))
PLUGIN_CCFLAGS		= $(CFLAGS) -Wall -fPIC
PLUGIN_LDFLAGS		= $(LDFLAGS) -shared

.PHONY: all
all: $(PLUGIN)

$(PLUGIN): $(PLUGIN_OBJ)
	$(CC) $(PLUGIN_OBJ) $(PLUGIN_LDFLAGS) -o $@

%.o: %.c
	$(CC) $(PLUGIN_CCFLAGS) $(PLUGIN_INCLUDES) -c $*.c -o $*.o

.PHONY: clean
clean:
	$(RM) $(PLUGIN_OBJ) $(PLUGIN_UUID).plugin

