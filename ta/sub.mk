global-incdirs-y += ./include
global-incdirs-y += ../libnts/
global-incdirs-y += ../libnts-log2syslog/nts-log2syslog/ ../libnts-log2syslog
srcs-y += io.c musl.c nts_ta.c checksum.c adler32.c

TA_NAME=ntsta

# prepend every log message the origin by defining LOGPREFIX and LOGPOSTFIX suitably
VERBOSE_LOGMESSAGE_ORIGIN= -DLOGPREFIX='"$(TA_NAME) at %s in %s line %d: "' -DLOGPOSTFIX=', __FUNCTION__, __FILE__, __LINE__'

WARNING_OPTIONS=-Wall -Wextra -Wconversion -Wsign-conversion -Wsign-compare -Wpointer-arith -Wstrict-overflow=5 -Wmissing-prototypes -Wmissing-declarations -Wredundant-decls -Werror=format-security -Werror=implicit-function-declaration -Wtype-limits -Wfree-nonheap-object
GCC_OPTIONS=-O2 -fno-strict-overflow -D_FORTIFY_SOURCE=1

CFLAGS += $(WARNING_OPTIONS) $(GCC_OPTIONS) -DLIBNTS_DECLARE_BASICS_MISSING_IN_OPTEEE $(VERBOSE_LOGMESSAGE_ORIGIN) $(WARNING_OPTIONS) $(INCLUDES)

libnames += wolfssl nts nts-log2syslog
libdirs += ../crypto/ ../libnts/ ../libnts-log2syslog/ $(LINKING)
libdeps += ../crypto/libwolfssl.a ../libnts/libnts.a ../libnts-log2syslog/libnts-log2syslog.a

