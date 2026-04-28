include $(TOPDIR)/rules.mk

PKG_NAME:=netguard
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_LICENSE:=MIT
PKG_MAINTAINER:=NetGuard

include $(TOPDIR)/include/package.mk

define Package/netguard
  SECTION:=net
  CATEGORY:=Network
  TITLE:=NetGuard - Network Monitor for OpenWrt
  DEPENDS:=@Linux
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)/src
endef

define Build/Compile
	cd $(PKG_BUILD_DIR)/src && \
	cargo build --release --target=x86_64-openwrt-linux-musl
endef

define Package/netguard/install
	$(CP) $(PKG_BUILD_DIR)/src/target/x86_64-openwrt-linux-musl/release/netguard $(1)/usr/bin/
	$(CP) ./root/* $(1)/
endef

$(eval $(call BuildPackage,netguard))
