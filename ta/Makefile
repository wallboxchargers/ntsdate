CFG_TEE_TA_LOG_LEVEL ?= 5
CFLAGS += -Wall -I../inetsocket/include -I./include -I../crypto/wolfssl/
LDFLAGS += -static -lwolfssl -lutils

# The UUID for the Trusted Application
BINARY=9a743b32-06a5-4e32-bf15-82de3dc49472

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ldargs-$(binary).elf += wolfssl

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@echo 'Note: $$(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk not found, cannot clean TA'
	@echo 'Note: TA_DEV_KIT_DIR=$(TA_DEV_KIT_DIR)'
endif
