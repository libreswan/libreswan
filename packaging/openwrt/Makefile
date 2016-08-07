#
# Copyright (C) 2006-2009 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=libreswan
PKG_VERSION:3.18
PKG_RELEASE:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION).tar.gz
PKG_SOURCE_URL:=https://download.libreswan.org/testing/
PKG_MD5SUM:=calculate_me

include $(INCLUDE_DIR)/package.mk

define Package/libreswan/Default
  TITLE:=Libreswan
  URL:=http://www.libreswan.org/
  DEPENDS:=@LINUX_2_6
endef

define Package/libreswan/Default/description
 Libreswan is an IPsec implementation for Linux.
endef

define Package/libreswan
$(call Package/libreswan/Default)
  SUBMENU:=VPN
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=+kmod-libreswan +ip
  TITLE+= (daemon)
endef

define Package/libreswan/description
$(call Package/libreswan/Default/description)
 This package contains the Libreswan user-land daemon.
endef

define KernelPackage/libreswan
$(call Package/libreswan/Default)
  SUBMENU:=Network Support
  TITLE+= (kernel module)
  FILES:=$(PKG_BUILD_DIR)/modobj*/ipsec.$(LINUX_KMOD_SUFFIX)
endef

define KernelPackage/libreswan/description
$(call Package/libreswan/Default/description)
 This package contains the Libreswan kernel module.
endef

TARGET_CPPFLAGS += -I$(LINUX_DIR)/include

LIBRESWAN_MAKE := $(MAKE) -C $(PKG_BUILD_DIR) \
	$(TARGET_CONFIGURE_OPTS) \
	LINUX_RELEASE="$(LINUX_RELEASE)" \
	KERNELSRC="$(LINUX_DIR)" \
	ARCH="$(LINUX_KARCH)" \
	CROSS_COMPILE="$(TARGET_CROSS)" \
	USERCOMPILE="$(TARGET_CFLAGS) -I$(PKG_BUILD_DIR)/ports/linux/include -I$(PKG_BUILD_DIR)/linux/include -I$(PKG_BUILD_DIR)/include $(TARGET_CPPFLAGS) $(TARGET_LDFLAGS)" \
	IPSECDIR="/usr/lib/ipsec" \
	INC_USRLOCAL="/usr" \
	INC_RCDEFAULT="/etc/init.d" \
	MODPROBE="/sbin/insmod" \
	USE_DNSSEC=false \
	USE_LINUX_AUDIT=false \
	USE_LABELED_IPSEC=false \
	LDFLAGS="$(TARGET_LDFLAGS)" \
	DESTDIR="$(PKG_INSTALL_DIR)"

define Build/Compile
	$(LIBRESWAN_MAKE) \
		programs module install
endef

define Package/libreswan/install
	$(CP) $(PKG_INSTALL_DIR)/* $(1)
	$(INSTALL_DIR) $(1)/etc/init.d
	$(CP) ./files/ipsec.init $(1)/etc/init.d/ipsec
	rm -rf $(1)/usr/share
	rm -rf $(1)/usr/man
	rm -rf $(1)/var
	rm -rf $(1)/etc/rc.d
	find $(1) -name \*.old | xargs rm -rf
endef

$(eval $(call BuildPackage,libreswan))
$(eval $(call KernelPackage,libreswan))
