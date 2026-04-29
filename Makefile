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
  DEPENDS:=+libc +libpthread +librt +libsqlite3 +kmod-nft-core +kmod-nft-bridge
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Configure
	cd $(PKG_BUILD_DIR) && cargo configure --release --target=x86_64-unknown-linux-musl
endef

define Build/Compile
	cd $(PKG_BUILD_DIR) && cargo build --release --target=x86_64-unknown-linux-musl
endef

define Package/netguard/install
	$(CP) $(PKG_BUILD_DIR)/target/x86_64-unknown-linux-musl/release/netguard $(1)/usr/bin/
	chmod +x $(1)/usr/bin/netguard
	$(CP) ./root/* $(1)/
	find $(1) -type f -name "*.json" -exec chmod 644 {} \;
endef

$(eval $(call BuildPackage,netguard))