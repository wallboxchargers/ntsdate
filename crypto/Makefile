CC      ?= $(CROSS_COMPILE)gcc
LD      ?= $(CROSS_COMPILE)ld
AR      ?= $(CROSS_COMPILE)ar
NM      ?= $(CROSS_COMPILE)nm
OBJCOPY ?= $(CROSS_COMPILE)objcopy
OBJDUMP ?= $(CROSS_COMPILE)objdump
READELF ?= $(CROSS_COMPILE)readelf

LIBNAME = libwolfssl

wolf_subdir=wolfssl

wolf_files_internal = \
  wolfcrypt/src/hmac.c \
  wolfcrypt/src/cpuid.c \
  wolfcrypt/src/kdf.c \
  wolfcrypt/src/random.c \
  wolfcrypt/src/rsa.c \
  wolfcrypt/src/aes.c \
  wolfcrypt/src/cmac.c \
  wolfcrypt/src/dsa.c \
  wolfcrypt/src/sha.c \
  wolfcrypt/src/sha256.c \
  wolfcrypt/src/sha3.c \
  wolfcrypt/src/sha512.c \
  wolfcrypt/src/error.c \
  wolfcrypt/src/wc_encrypt.c \
  wolfcrypt/src/signature.c \
  wolfcrypt/src/wolfmath.c \
  wolfcrypt/src/memory.c \
  wolfcrypt/src/logging.c \
  wolfcrypt/src/sp_int.c \
  wolfcrypt/src/dh.c \
  wolfcrypt/src/asn.c \
  wolfcrypt/src/coding.c \
  wolfcrypt/src/poly1305.c \
  wolfcrypt/src/md5.c \
  wolfcrypt/src/pwdbased.c \
  wolfcrypt/src/chacha.c \
  wolfcrypt/src/chacha20_poly1305.c \
  wolfcrypt/src/ecc.c \
  src/internal.c \
  src/wolfio.c \
  src/keys.c \
  src/ssl.c \
  src/tls.c \
  src/tls13.c \
  wolfcrypt/src/hash.c \
  wolfcrypt/src/tfm.c \
  wolfcrypt/src/wc_port.c \

# ask wolfssl to honor our user_settings.h
WOLF_SSL_FLAGS += -DWOLFSSL_USER_SETTINGS

WOLF_CHANGES_WRT_C89 += -fno-strict-aliasing
WOLF_WARNING_SUPPRESS += -Wno-unused-function -Wno-switch-default
WARNING_OPTIONS=-Wall -Wextra -Wconversion -Wsign-conversion -Wsign-compare -Wpointer-arith -Wstrict-overflow=5 -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Werror=format-security -Werror=implicit-function-declaration -Wtype-limits -Wfree-nonheap-object
GCC_OPTIONS=-O2 -fPIC -fno-strict-overflow -D_GNU_SOURCE -D_FORTIFY_SOURCE=1
LIBNTS_INCLUDES=-I../libnts -I../libnts/nts

CFLAGS += $(WARNING_OPTIONS) $(GCC_OPTIONS) \
	$(WOLF_SSL_FLAGS) $(INCLUDE_OVERWRITES) $(WOLF_WARNING_SUPPRESS) $(WOLF_CHANGES_WRT_C89) \
	$(LIBNTS_INCLUDES) $(INCLUDES)

# prepend every log message the origin by defining LOGPREFIX and LOGPOSTFIX suitably
VERBOSE_LOGMESSAGE_ORIGIN= -DLOGPREFIX='"$(LIBNAME) at %s in %s line %d: "' -DLOGPOSTFIX=', __FUNCTION__, __FILE__, __LINE__'

STATICLIB		= $(LIBNAME).a
LIB_SRS		= $(foreach wfile, $(wolf_files_internal), $(wolf_subdir)/$(wfile))
LIB_OBJ		= $(patsubst %.c, %.o, $(LIB_SRS))
LIB_INCLUDES_DIR	= $(CURDIR)/wolfssl
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

