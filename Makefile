# ntsdate - a minimalistic RFC8915 implementation
# Copyright (C) 2024: ABL GmbH
#
# This program is available under two distinct licenses:
# You may either choose to
#  a) adhere to the GNU General Public License version 2,
#     as published by the Free Software Foundation, or
#  b) obtain a commercial license from ABL GmbH,
#     Albert-Büttner-Straße 11, 91207 Lauf an der Pegnitz, Germany.

export V?=0

#SHELL="bash -x"
# If HOST_ or TA_ specific compilers are not specified, then use CROSS_COMPILE
HOST_CROSS_COMPILE ?= $(CROSS_COMPILE)
TA_CROSS_COMPILE ?= $(CROSS_COMPILE)

HOST_INCLUDES=
TA_INCLUDES=-I$(TA_DEV_KIT_DIR)/include
TA_LINKING=-L$(TA_DEV_KIT_DIR)/lib -lutils

ntsdate: libs-host
	$(MAKE) -C ntsdate CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables

.PHONY: libs-host
libs-host:
	$(MAKE) -C crypto CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables
	$(MAKE) -C libnts-log2syslog CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables
	$(MAKE) -C libnts-netio CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables
	$(MAKE) -C libnts CROSS_COMPILE="$(HOST_CROSS_COMPILE)" --no-builtin-variables

GENERATE_VERSION=./generate-version.sh
VERSION_HEADER=ta/version.h
TA_VERSION_ENV=ta/ta-version.env

ta: $(VERSION_HEADER) $(TA_VERSION_ENV) libs-ta
	$(MAKE) -C host CROSS_COMPILE="$(HOST_CROSS_COMPILE)" INCLUDES="$(HOST_INCLUDES)" --no-builtin-variables
	$(MAKE) -C inetsocket CROSS_COMPILE="$(HOST_CROSS_COMPILE)" INCLUDES="$(HOST_INCLUDES)" --no-builtin-variables
	$(MAKE) -C ta CROSS_COMPILE="$(TA_CROSS_COMPILE)" INCLUDES="$(TA_INCLUDES)" LDFLAGS="$(TA_LINKING)"

.PHONY: libs-ta
libs-ta:
	$(MAKE) -C crypto CROSS_COMPILE="$(TA_CROSS_COMPILE)" INCLUDES="$(TA_INCLUDES)" --no-builtin-variables
	$(MAKE) -C libnts-log2syslog CROSS_COMPILE="$(HOST_CROSS_COMPILE)" INCLUDES="$(HOST_INCLUDES)" --no-builtin-variables
	$(MAKE) -C libnts-netio CROSS_COMPILE="$(HOST_CROSS_COMPILE)" INCLUDES="$(HOST_INCLUDES)" --no-builtin-variables
	$(MAKE) -C libnts CROSS_COMPILE="$(TA_CROSS_COMPILE)" INCLUDES="$(TA_INCLUDES)" --no-builtin-variables

$(VERSION_HEADER):
	@echo === Preparing version info ===
	$(GENERATE_VERSION) $(VERSION_HEADER)

$(TA_VERSION_ENV):
	@echo === Preparing ta version env ===
	$(GENERATE_VERSION) $(TA_VERSION_ENV)

# whether to delete rather permanent files like TA_VERSION_ENV file upon "make clean"
#PURGE_ADDITIONALLY=$(TA_VERSION_ENV)
PURGE_ADDITIONALLY=

possiblytobecleanedfilesandfolders = $(VERSION_HEADER) $(PURGE_ADDITIONALLY) .generated_version crypto/out ta/out libnts/out libnts-netio/out libnts/.*.o.cmd ta/.*.o.cmd ta/*/.*.o.cmd crypto/wolfssl/src/.*.o.cmd crypto/wolfssl/wolfcrypt/src/.*.o.cmd
tobecleanedfilesandfolders = $(foreach f,$(possiblytobecleanedfilesandfolders),$(wildcard $(f)))


.PHONY: clean
clean:
	rm -rf $(tobecleanedfilesandfolders)
	$(MAKE) -C crypto clean
	$(MAKE) -C libnts-netio clean
	$(MAKE) -C libnts-log2syslog clean
	$(MAKE) -C libnts clean
	$(MAKE) -C ntsdate clean
	$(MAKE) -C inetsocket clean
