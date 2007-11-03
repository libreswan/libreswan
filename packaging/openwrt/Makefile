# $Id: Makefile,v 1.1.2.5 2007/07/17 19:43:26 paul Exp $

include $(TOPDIR)/rules.mk

PKG_NAME:=openswan
PKG_VERSION:=2.4.9
PKG_RELEASE:=7
PKG_MD5SUM:=c6f3714bf39b91a80633ec3aa7fce298

PKG_SOURCE_URL:=http://www.openswan.org/download
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)
PKG_CAT:=zcat

include $(TOPDIR)/package/rules.mk

$(eval $(call PKG_template,OPENSWAN,openswan,$(PKG_VERSION)-$(PKG_RELEASE),$(ARCH)))

FLAGS := $(TARGET_CFLAGS) -I$(PKG_BUILD_DIR)/linux/include -L$(STAGING_DIR)/usr/lib -I$(STAGING_DIR)/usr/include

$(PKG_BUILD_DIR)/.built:
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		KERNELSRC="$(LINUX_DIR)" \
		ARCH="mips" \
		USERCOMPILE="$(FLAGS)" \
		LD_LIBRARY_PATH="$(STAGING_DIR)/usr/lib" \
		EXTRA_INCLUDE="-I$(STAGING_DIR)/usr/include" \
		IPSECDIR="/usr/lib/ipsec" \
		INC_USRLOCAL="/usr" \
		INC_RCDEFAULT="/etc/init.d" \
		MODPROBE="/sbin/insmod" \
		programs

$(IPKG_OPENSWAN):
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		DESTDIR="$(IDIR_OPENSWAN)" \
		KERNELSRC="$(LINUX_DIR)" \
		ARCH="mips" \
		USERCOMPILE="$(FLAGS)" \
		IPSECDIR="/usr/lib/ipsec" \
		INC_USRLOCAL="/usr" \
		INC_RCDEFAULT="/etc/init.d" \
		MODPROBE="/sbin/insmod" \
		install
	-$(STRIP) $(IDIR_OPENSWAN)/usr/lib/ipsec/*
	-$(STRIP) $(IDIR_OPENSWAN)/usr/libexec/ipsec/*
	rm -rf $(IDIR_OPENSWAN)/usr/share
	rm -rf $(IDIR_OPENSWAN)/usr/man
	rm -rf $(IDIR_OPENSWAN)/var
	rm -rf $(IDIR_OPENSWAN)/etc/rc.d/rc*.d
	mkdir -p $(IDIR_OPENSWAN)/etc/init.d
	ln -sf ipsec $(IDIR_OPENSWAN)/etc/init.d/S60ipsec
	find $(PKG_BUILD_DIR) -name \*.old | xargs rm -rf
	mkdir -p $(PACKAGE_DIR)
	$(IPKG_BUILD) $(IDIR_OPENSWAN) $(PACKAGE_DIR)
