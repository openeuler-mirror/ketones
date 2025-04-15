include ../common.mk

TARGET_ALIAS := $(addprefix $(BINARIES_DIR)/, bcachefsslower btrfsslower ext4slower \
			nfsslower xfsslower zfsslower f2fsslower)
$(eval $(call alias-override,$(TARGET_ALIAS),$(TARGET)))
