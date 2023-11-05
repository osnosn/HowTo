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

* 我用的是CentOS7.
* `yum install hostapd` 我装的版本是2.6
* 进入 `/etc/hostapd/` 目录。
* 创建以下三个文件。
* 根据文末提示的链接，创建所需的证书。
* `hostapd -dd /etc/hostapd/hostapd.conf` 前台运行，测试一下。按`ctrl-c`退出。
* `service hostapd start` 启动服务正式工作。

hostapd.conf
```
# hostapd.conf
# 文件中所有配置的路径，要使用绝对路径。hostapd不认相对路径。
driver=none
ieee8021x=1
eap_server=1
eap_user_file=/etc/hostapd/hostapd.eap_user
radius_server_clients=/etc/hostapd/hostapd.radius_clients
radius_server_auth_port=1812

server_cert=/etc/hostapd/server_cert.pem
private_key=/etc/hostapd/server_key.pem
ca_cert=/etc/hostapd/ca_cert+crl.pem
check_crl=1

logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
```

hostapd.eap_user
```
# hostapd.eap_user
*  PEAP,TLS

"user1"  MSCHAPV2  "pass1"  [2]
"user2"  MSCHAPV2  "pass2"  [2]
#guest
"user3"  MSCHAPV2  "pass3"  [2]
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
