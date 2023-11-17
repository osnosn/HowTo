## [CentOS7: using hostapd as a radius server to provide wifi 802.1x Enterprise Authentication](https://github.com/osnosn/HowTo/blob/master/Linux/CentOS7_hostapd_radius_WIFI_802.1x_EAP-PEAP_EAP-TLS_EnterpriseAuthentication.md)
support EAP-PEAP,EAP-TLS.

## [CentOS7用hostapd做radius服务器为WiFi提供802.1X企业认证](https://www.cnblogs.com/osnosn/p/10593297.html)
支持 EAP-PEAP, EAP-TLS。   写于: 2019-03-27.

> 家里的WiFi一般是用WPA2认证，密码只有一个，泄漏了，家里所有设备都要换密码。  
> 再加上现在密码共享软件的流行，如“wifi万能钥匙”，WPA2的密码也不安全了。  
> 本文介绍如何搭建一个EAP的企业认证WiFi。支持N个账号(N>=1)，可以做到一人一个账号。  
> 一个账号泄漏，改掉这个账号的密码，或者删除这个账号就行。  
> 如果你不嫌麻烦，还可以发放一人一个证书认证上网。证书本身有过期时间的，还能吊销。  
> 过期证书或被吊销证书，是不能登陆WiFi的。  

支持 EAP-PEAP(msCHAPv2) 用户账号认证。用户账号存于文本文件中。   
EAP-TLS证书认证，证书自行生成，可以吊销单个证书而阻止再次连接。

> 本文参考了几位大神的文章:   
> 　[拒绝万能钥匙!教您用hostapd搭建一个企业级的Wi-Fi](https://zhuanlan.zhihu.com/p/28439127)，  
> 　[搭建一个「最安全」的Wi-Fi网络](https://zhuanlan.zhihu.com/p/28927420)，[楠站](https://zenandidi.com/?s=hostapd)，  
> 　[将hostapd作为radius服务器搭建EAP认证环境](https://www.cnblogs.com/claruarius/p/5902141.html)，  
> 　[802.1X企业级加密](https://www.cnblogs.com/sun3596209/p/3226832.html),  
> 
> 其他链接  
> * [hostapd 源码.文件树](https://w1.fi/cgit/hostap/tree/hostapd)，  
> * [openwrt 有线wired802.1x认证](https://blog.csdn.net/weixin_44053794/article/details/132880887)  
> * [hostapd 代码分析-完全的802.1X认证过程（radius服务器）](https://blog.csdn.net/u012503786/article/details/79292211)  
> * [搭建openwrt企业级认证-快速漫游的简单过程与常见问题_802.11r_EAP_FT-EAP_hostapd operation not permited_no r0kh matched](https://blog.csdn.net/Mr_liu_666/article/details/125648948)  

## 其他搭建方法
* 这篇帖子的做法，更好: 【[OpenWrt 用 hostapd 作为 Radius 服务器配置 WPAx-EAP 认证](https://blog.azuk.top/posts/openwrt-hostapd-radius-server/)】
  * 在op的 SDK 目录中，修改
    ```
    # vim feeds/base/package/network/services/hostapd/files/hostapd-full.config
	# 找到并启用这两行
	CONFIG_DRIVER_NONE=y
	CONFIG_RADIUS_SERVER=y
    ```
  * 编译wpad-openssl 或 hostapd-opensssl 软件包
  * op中，新建系统服务 "/etc/init.d/hostapd-radius"
    ```bash
	#!/bin/sh /etc/rc.common
	START=90
	USE_PROCD=1
	NAME=hostapd-radius
	start_service() {
	   if [ -x "/usr/sbin/hostapd" ]; then
	      procd_open_instance hostapd-radius
	      procd_set_param command /usr/sbin/hostapd -s /etc/hostapd/hostapd.conf
	      procd_set_param respawn 3600 1 0
	      [ -x /sbin/ujail -a -e /etc/capabilities/wpad.json ] && {
	         procd_add_jail hostapd-radius
	         procd_set_param capabilities /etc/capabilities/wpad.json
	         procd_set_param user network
	         procd_set_param group network
	         procd_set_param no_new_privs 1
	      }
	      procd_close_instance
	   fi
	}
	```
  * 启用并启动服务。
	```bash
	/etc/init.d/hostapd-radius enable
	/etc/init.d/hostapd-radius start
	```


## 安装配置
### 安装 hostapd 软件包
* 我用的是CentOS7.
* `yum install hostapd` 我装的版本是2.6
* 进入 `/etc/hostapd/` 目录。
* 创建以下三个文件。
* 根据文末提示的链接，创建所需的证书。
* `hostapd -dd /etc/hostapd/hostapd.conf` 前台运行，测试一下。按`ctrl-c`退出。
* `service hostapd start` 启动服务正式工作。

hostapd.conf  
参考官方文档 [hostapd.conf](https://w1.fi/cgit/hostap/tree/hostapd/hostapd.conf)，  
```
# hostapd.conf
# All path MUST be absolute path.
# 文件中所有配置的路径，要使用绝对路径。hostapd不认相对路径。
driver=none
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd/hostapd.eap_user
radius_server_clients=/etc/hostapd/hostapd.radius_clients
radius_server_auth_port=1812

ca_cert=/etc/hostapd/ca_cert+crl.pem
server_cert=/etc/hostapd/server_cert.pem
private_key=/etc/hostapd/server_key.pem
# 备用服务器证书配置，主要用于同时启用RSA和ECC公钥。但可能有兼容性问题。
#server_cert2=/etc/hostapd/server_cert-ecc.pem
#private_key2=/etc/hostapd/server_key-ecc.pem

# 0 = do not verify CRLs (default)
# 1 = check the CRL of the user certificate
# 2 = check all CRLs in the certificate path
check_crl=1

logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2

# ---以下的配置项，未测试---
# 忽略user证书的有效期,禁用v1.0,v1.1,启用v1.3
#tls_flags=[DISABLE-TIME-CHECKS][DISABLE-TLSv1.0][DISABLE-TLSv1.1][ENABLE-TLSv1.3]
# 缓存OCSP装订,请看官方文档。Cached OCSP stapling response (DER encoded)
#ocsp_stapling_response=/tmp/ocsp-cache.der
```

hostapd.eap_user  
参考官方文档 [hostapd.eap_user](https://w1.fi/cgit/hostap/tree/hostapd/hostapd.eap_user)，  
```
# hostapd.eap_user
# Phase 1 users
# 指定匿名身份, 写多行, 按顺序匹配。
#"user4"  TTLS
#"user5"  TLS
# `*` 表示,匿名身份随便写,只能有一行,因为它一定会被匹配。后续的配置行失效。因为后续行,不会被匹配。
# `*` anonymous identities: input anything is OK.
#*  PEAP,TLS,TTLS
*  PEAP,TLS

# Phase 2 users
# MSCHAPV2 用于PEAP
# TTLS-PAP,TTLS-MSCHAP,TTLS-MSCHAPV2 用于TTLS
"user1"  MSCHAPV2  "pass1"  [2]
"user2"  MSCHAPV2  "pass2"  [2]
# 上面给自家用，下面给客人用
"user3"  MSCHAPV2  "pass3"  [2]

"tuser4"  TTLS-MSCHAPV2  "tpass4"  [2]
```
> 如果 仅需要PEAP， 就写 `*  PEAP`，下面写账号，一行一个账号。  
> 如果 仅需要TLS， 就写 `*  TLS`，下面的账号就不需要了，写了也没用，不会用到。  
> 此项配置不能写成两行，hostapd不认，一定要写成一行`*  PEAP,TLS`，多种认证方式用逗号分隔。  

hostapd.radius_clients  
```
# hostapd.radius_clients
192.168.5.0/24   key1234
#0.0.0.0/0        key5678
```
EAP-TLS 认证中**用到的证书**，见我写的另一文 **"[用openssl为PEAP/EAP-TLS生成证书（CA证书,服务器证书,用户证书）](https://github.com/osnosn/HowTo/blob/master/OpenSSL/Create_CERTs_for_PEAP_EAP-TLS_using_openssl.md)"**。   
AP设备的认证设置，客户端的连接设置，请参看页头**大神**的文章。   

--------- end ---------
