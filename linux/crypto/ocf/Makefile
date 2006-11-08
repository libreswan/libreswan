
ifdef obj
my_inc_base = $(obj)
else
my_inc_base = .
O_TARGET := ocfdrv.o
endif

# for SGlinux builds
-include $(ROOTDIR)/modules/.config

obj-$(CONFIG_OCF_OCF)        += $(obj-base)ocf.o
obj-$(CONFIG_OCF_CRYPTODEV)  += $(obj-base)cryptodev.o
obj-$(CONFIG_OCF_CRYPTOSOFT) += $(obj-base)cryptosoft/

obj-$(CONFIG_OCF_SAFE)       += $(obj-base)safe/
obj-$(CONFIG_OCF_HIFN)       += $(obj-base)hifn/
obj-$(CONFIG_OCF_IXP4XX)     += $(obj-base)ixp4xx/
obj-$(CONFIG_OCF_TALITOS)    += $(obj-base)talitos/
obj-$(CONFIG_OCF_OCFNULL)    += $(obj-base)ocfnull/

obj-$(CONFIG_OCF_BENCH)      += $(obj-base)ocf-bench.o

ifndef obj
list-multi += ocf.o 
export-objs += crypto.o criov.o random.o
endif

ocf-objs   := $(obj-base)crypto.o $(obj-base)criov.o $(obj-base)random.o

ifdef CONFIG_OCF_FIPS
ocf-objs     += $(obj-base)rndtest.o
EXTRA_CFLAGS += -DFIPS_TEST_RNG
endif

EXTRA_CFLAGS += -I$(my_inc_base)/.

#
# You will need to point this at your Intel ixp425 includes,  this portion
# of the Makefile only really works under SGLinux with the appropriate libs
# installed.  They can be downloaded from http://www.snapgear.org/
#

ifdef CONFIG_IXP400_LIB_2_0
IX_XSCALE_SW = $(ROOTDIR)/modules/ixp425/ixp400-2.0/ixp400_xscale_sw
OSAL_DIR     = $(ROOTDIR)/modules/ixp425/ixp400-2.0/ixp_osal

IXP_CFLAGS = \
	-I$(ROOTDIR)/. \
	-I$(IX_XSCALE_SW)/src/include \
	-I$(OSAL_DIR)/ \
	-I$(OSAL_DIR)/os/linux/include/ \
	-I$(OSAL_DIR)/os/linux/include/modules/ \
	-I$(OSAL_DIR)/os/linux/include/modules/ioMem/ \
	-I$(OSAL_DIR)/os/linux/include/modules/core/ \
	-I$(OSAL_DIR)/os/linux/include/modules/bufferMgt/ \
	-I$(OSAL_DIR)/os/linux/include/core/  \
	-I$(OSAL_DIR)/os/linux/include/platforms/ \
	-I$(OSAL_DIR)/os/linux/include/platforms/ixp400/ \
	-I$(OSAL_DIR)/os/linux/include/platforms/ixp400/ixp425 \
	-I$(OSAL_DIR)/os/linux/include/platforms/ixp400/ixp465 \
	-I$(OSAL_DIR)/os/linux/include/core/ \
	-I$(OSAL_DIR)/include/ \
	-I$(OSAL_DIR)/include/modules/ \
	-I$(OSAL_DIR)/include/modules/bufferMgt/ \
	-I$(OSAL_DIR)/include/modules/ioMem/ \
	-I$(OSAL_DIR)/include/modules/core/ \
	-I$(OSAL_DIR)/include/platforms/ \
	-I$(OSAL_DIR)/include/platforms/ixp400/ \
	-I$(OSAL_DIR)/include/platforms/ixp400/ixp425 \
	-I$(OSAL_DIR)/include/platforms/ixp400/ixp465 \
	-I$(IX_XSCALE_SW)/src/linux \
	-DUSE_IXP4XX_CRYPTO
endif
ifdef CONFIG_IXP400_LIB_1_4
IXP_CFLAGS   = \
	-I$(ROOTDIR)/. \
	-I$(ROOTDIR)/modules/ixp425/ixp400-1.4/ixp400_xscale_sw/src/include \
	-I$(ROOTDIR)/modules/ixp425/ixp400-1.4/ixp400_xscale_sw/src/linux \
	-DUSE_IXP4XX_CRYPTO
endif
ifndef IXPDIR
IXPDIR = ixp-version-is-not-supported
endif

ifeq ($(CONFIG_MACH_IXDP465),y)
IXP_CFLAGS += -D__ixp46X
else
IXP_CFLAGS += -D__ixp42X
endif

CFLAGS_ixp4xx/ixp4xx.o += $(IXP_CFLAGS)
CFLAGS_ixp4xx.o += $(IXP_CFLAGS)
CFLAGS_ocf-bench.o += $(IXP_CFLAGS)

ifdef TOPDIR
-include $(TOPDIR)/Rules.make
endif

.PHONY: clean mrproper distclean
clean:
	rm -f $(obj-m) *.o *.ko .*.o.flags .*.ko.cmd .*.o.cmd .*.mod.o.cmd *.mod.c
	rm -f */*.o */*.ko */.*.o.cmd */.*.ko.cmd */.*.mod.o.cmd */*.mod.c */.*.o.flags

mrproper: clean
	rm -f .depend
distclean: mrproper

$(obj-base)ocf.o: $(ocf-objs)
	$(LD) -r -o $@ $(ocf-objs)

.PHONY: patch
patch:
	REL=`date +%Y%m%d`; \
		patch=ocf-linux-$$REL.patch; \
		patch24=ocf-linux-24-$$REL.patch; \
		patch26=ocf-linux-26-$$REL.patch; \
		( \
			find . -name Makefile; \
			find . -name Config.in; \
			find . -name Kconfig; \
			find . -name README; \
			find . -name '*.[ch]' | grep -v '.mod.c'; \
		) | while read t; do \
			diff -Nau /dev/null $$t | sed 's?^+++ \./?+++ linux/crypto/ocf/?'; \
		done > $$patch; \
		cat patches/linux-2.4.29-ocf.patch $$patch > $$patch24; \
		cat patches/linux-2.6.11-ocf.patch $$patch > $$patch26

.PHONY: tarball
tarball:
	REL=`date +%Y%m%d`; RELDIR=/tmp/ocf-linux-$$REL; \
		CURDIR=`pwd`; \
		rm -rf /tmp/ocf-linux-$$REL*; \
		mkdir -p $$RELDIR/tools; \
		cp README* $$RELDIR; \
		cp patches/ss?.patch $$RELDIR; \
		cp patches/crypto-tools.patch $$RELDIR; \
		cp tools/[!C]* $$RELDIR/tools; \
		cd ..; \
		tar cvf $$RELDIR/ocf-linux.tar \
					--exclude=CVS \
					--exclude=.* \
					--exclude=*.o \
					--exclude=*.ko \
					--exclude=*.mod.* \
					--exclude=README* \
					--exclude=ocf-*.patch \
					--exclude=ocf/patches/ss?.patch \
					--exclude=ocf/patches/crypto-tools.patch \
					--exclude=ocf/tools \
					ocf; \
		gzip -9 $$RELDIR/ocf-linux.tar; \
		cd /tmp; \
		tar cvf ocf-linux-$$REL.tar ocf-linux-$$REL; \
		gzip -9 ocf-linux-$$REL.tar; \
		cd $$CURDIR/../../user; \
		rm -rf /tmp/crypto-tools-$$REL*; \
		tar cvf /tmp/crypto-tools-$$REL.tar \
					--exclude=CVS \
					--exclude=.* \
					--exclude=*.o \
					--exclude=cryptotest \
					--exclude=cryptokeytest \
					crypto-tools; \
		gzip -9 /tmp/crypto-tools-$$REL.tar


ifdef obj
my_inc_base = $(obj)
else
my_inc_base = .
O_TARGET := ocfdrv.o
endif

# for SGlinux builds
-include $(ROOTDIR)/modules/.config

obj-$(CONFIG_OCF_OCF)        += $(obj-base)ocf.o
obj-$(CONFIG_OCF_CRYPTODEV)  += $(obj-base)cryptodev.o
obj-$(CONFIG_OCF_CRYPTOSOFT) += $(obj-base)cryptosoft/

obj-$(CONFIG_OCF_SAFE)       += $(obj-base)safe/
obj-$(CONFIG_OCF_HIFN)       += $(obj-base)hifn/
obj-$(CONFIG_OCF_IXP4XX)     += $(obj-base)ixp4xx/
obj-$(CONFIG_OCF_TALITOS)    += $(obj-base)talitos/
obj-$(CONFIG_OCF_OCFNULL)    += $(obj-base)ocfnull/

obj-$(CONFIG_OCF_BENCH)      += $(obj-base)ocf-bench.o

obj-$(CONFIG_OCF_RANDOMHARVEST) += $(obj-base)random.o

ifndef obj
list-multi += ocf.o 
export-objs += crypto.o criov.o 
endif

ocf-objs   := $(obj-base)crypto.o $(obj-base)criov.o 

ifdef CONFIG_OCF_FIPS
ocf-objs     += $(obj-base)rndtest.o
EXTRA_CFLAGS += -DFIPS_TEST_RNG
endif

EXTRA_CFLAGS += -I$(my_inc_base)/.

#
# You will need to point this at your Intel ixp425 includes,  this portion
# of the Makefile only really works under SGLinux with the appropriate libs
# installed.  They can be downloaded from http://www.snapgear.org/
#

ifdef CONFIG_IXP400_LIB_2_0
IX_XSCALE_SW = $(ROOTDIR)/modules/ixp425/ixp400-2.0/ixp400_xscale_sw
OSAL_DIR     = $(ROOTDIR)/modules/ixp425/ixp400-2.0/ixp_osal

IXP_CFLAGS = \
	-I$(ROOTDIR)/. \
	-I$(IX_XSCALE_SW)/src/include \
	-I$(OSAL_DIR)/ \
	-I$(OSAL_DIR)/os/linux/include/ \
	-I$(OSAL_DIR)/os/linux/include/modules/ \
	-I$(OSAL_DIR)/os/linux/include/modules/ioMem/ \
	-I$(OSAL_DIR)/os/linux/include/modules/core/ \
	-I$(OSAL_DIR)/os/linux/include/modules/bufferMgt/ \
	-I$(OSAL_DIR)/os/linux/include/core/  \
	-I$(OSAL_DIR)/os/linux/include/platforms/ \
	-I$(OSAL_DIR)/os/linux/include/platforms/ixp400/ \
	-I$(OSAL_DIR)/os/linux/include/platforms/ixp400/ixp425 \
	-I$(OSAL_DIR)/os/linux/include/platforms/ixp400/ixp465 \
	-I$(OSAL_DIR)/os/linux/include/core/ \
	-I$(OSAL_DIR)/include/ \
	-I$(OSAL_DIR)/include/modules/ \
	-I$(OSAL_DIR)/include/modules/bufferMgt/ \
	-I$(OSAL_DIR)/include/modules/ioMem/ \
	-I$(OSAL_DIR)/include/modules/core/ \
	-I$(OSAL_DIR)/include/platforms/ \
	-I$(OSAL_DIR)/include/platforms/ixp400/ \
	-I$(OSAL_DIR)/include/platforms/ixp400/ixp425 \
	-I$(OSAL_DIR)/include/platforms/ixp400/ixp465 \
	-I$(IX_XSCALE_SW)/src/linux \
	-DUSE_IXP4XX_CRYPTO
endif
ifdef CONFIG_IXP400_LIB_1_4
IXP_CFLAGS   = \
	-I$(ROOTDIR)/. \
	-I$(ROOTDIR)/modules/ixp425/ixp400-1.4/ixp400_xscale_sw/src/include \
	-I$(ROOTDIR)/modules/ixp425/ixp400-1.4/ixp400_xscale_sw/src/linux \
	-DUSE_IXP4XX_CRYPTO
endif
ifndef IXPDIR
IXPDIR = ixp-version-is-not-supported
endif

ifeq ($(CONFIG_MACH_IXDP465),y)
IXP_CFLAGS += -D__ixp46X
else
IXP_CFLAGS += -D__ixp42X
endif

CFLAGS_ixp4xx/ixp4xx.o += $(IXP_CFLAGS)
CFLAGS_ixp4xx.o += $(IXP_CFLAGS)
CFLAGS_ocf-bench.o += $(IXP_CFLAGS)

ifdef TOPDIR
-include $(TOPDIR)/Rules.make
endif

.PHONY: clean mrproper distclean
clean:
	rm -f $(obj-m) *.o *.ko .*.o.flags .*.ko.cmd .*.o.cmd .*.mod.o.cmd *.mod.c
	rm -f */*.o */*.ko */.*.o.cmd */.*.ko.cmd */.*.mod.o.cmd */*.mod.c */.*.o.flags

mrproper: clean
	rm -f .depend
distclean: mrproper

$(obj-base)ocf.o: $(ocf-objs)
	$(LD) -r -o $@ $(ocf-objs)

.PHONY: patch
patch:
	REL=`date +%Y%m%d`; \
		patch=ocf-linux-$$REL.patch; \
		patch24=ocf-linux-24-$$REL.patch; \
		patch26=ocf-linux-26-$$REL.patch; \
		( \
			find . -name Makefile; \
			find . -name Config.in; \
			find . -name Kconfig; \
			find . -name README; \
			find . -name '*.[ch]' | grep -v '.mod.c'; \
		) | while read t; do \
			diff -Nau /dev/null $$t | sed 's?^+++ \./?+++ linux/crypto/ocf/?'; \
		done > $$patch; \
		cat patches/linux-2.4.29-ocf.patch $$patch > $$patch24; \
		cat patches/linux-2.6.11-ocf.patch $$patch > $$patch26

.PHONY: tarball
tarball:
	REL=`date +%Y%m%d`; RELDIR=/tmp/ocf-linux-$$REL; \
		CURDIR=`pwd`; \
		rm -rf /tmp/ocf-linux-$$REL*; \
		mkdir -p $$RELDIR/tools; \
		cp README* $$RELDIR; \
		cp patches/ss?.patch $$RELDIR; \
		cp patches/crypto-tools.patch $$RELDIR; \
		cp tools/[!C]* $$RELDIR/tools; \
		cd ..; \
		tar cvf $$RELDIR/ocf-linux.tar \
					--exclude=CVS \
					--exclude=.* \
					--exclude=*.o \
					--exclude=*.ko \
					--exclude=*.mod.* \
					--exclude=README* \
					--exclude=ocf-*.patch \
					--exclude=ocf/patches/ss?.patch \
					--exclude=ocf/patches/crypto-tools.patch \
					--exclude=ocf/tools \
					ocf; \
		gzip -9 $$RELDIR/ocf-linux.tar; \
		cd /tmp; \
		tar cvf ocf-linux-$$REL.tar ocf-linux-$$REL; \
		gzip -9 ocf-linux-$$REL.tar; \
		cd $$CURDIR/../../user; \
		rm -rf /tmp/crypto-tools-$$REL*; \
		tar cvf /tmp/crypto-tools-$$REL.tar \
					--exclude=CVS \
					--exclude=.* \
					--exclude=*.o \
					--exclude=cryptotest \
					--exclude=cryptokeytest \
					crypto-tools; \
		gzip -9 /tmp/crypto-tools-$$REL.tar

