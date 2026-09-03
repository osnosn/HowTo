# [openwrt-22.03_debian_centos_ocserv_haproxy_stunnel](https://github.com/osnosn/HowTo/blob/master/Linux/openwrt-22.03_debian_centos_ocserv_haproxy_stunnel.md)
**转载注明来源: [本文链接](https://github.com/osnosn/HowTo/blob/master/Linux/openwrt-22.03_debian_centos_ocserv_haproxy_stunnel.md)**，写于 2022-11-23.

# 前言
* 客户端：AnyConnect，由思科推出的客户端，目前已有支持Windows、Android、iOS、OS X、Ubuntu、WebOS等操作系统的版本；
* 也是基于SSL的加密连接。唯一的优点就是，openConnect的苹果客户端，叫 AnyConnect，国内市场就能免费装。
* win客户端【[gui.openconnect-vpn.net](https://gui.openconnect-vpn.net/download/)】【[gitlab](https://gitlab.com/openconnect/openconnect-gui/)】【[github](https://github.com/openconnect/openconnect-gui/releases)】
* win10,macOS,linux-gui 【[anylink-client](https://github.com/tlslink/anylink-client)】
* android 【[ics-openconnect](https://github.com/cernekee/ics-openconnect)】【[AnyLink-Secure-Client](https://github.com/shangjiyu/AnyLink-Secure-Client)】
* macOS 【[openconnectui2](https://github.com/rrva/openconnectui2)】【[SwiftConnect](https://github.com/wenyuzhao/SwiftConnect)】


# openwrt-21.02
* 网上有很多文章，自行搜索。

# openwrt-22.03
防火墙使用的是fw4，即nftables。  
## 安装配置
2022-11记录
### 安装 OpenConnect Server。
  ```
  opkg update
  opkg install ocserv luci-app-ocserv
  ```
  服务器证书，安装后就自动生成了。

### 去web页面配置。
* (2022-11测)
* Server Settings -> Gerneal Settings
  * Enable server: 勾上,启用服务
  * User Authentication: plain
  * Port: 默认 4443, (按需修改)
  * Max clients: 8, (按需修改)
  * Max same clients: 2, (按需修改)
  * Dead peer detection time: 默认 180secs
  * Predictable IPs: 默认勾上。
  * Enable compression: 勾上,启用压缩
  * Enable UDP: 默认勾上。
  * AnyConnect client compatibility: 默认勾上。
  * Enable proxy arp: 不勾。(如果勾上,IP段的配置需要深厚的知识)
  * VPN IPv4-Network-Address: 192.168.100.1 设置IPv4, 建议和 lan不一样网段。
  * VPN IPv4-Netmask: 255.255.255.0
  * VPN IPv6-Network-Address: 留空
  * DNS servers: 设置DNS server的IP。(推送给client用的),**建议测试一下,如果配错IP,对后面调试影响很大**
  * Routing table: 添加路由规则。(推送给client用的)
    * netmask，建议写数字。比如 "255.255.255.0" 写为 24 。这样不容易出错。
    * 如果想让客户端全局使用这个连接，只设置一个 0/0的缺省路由，IP:0, netmask:0,不要写 "0.0.0.0"
* Server Settings -> Edit Template，修改欢迎词。  
  `banner = "Welcome to MyHost"`  
* User Settings  
  * 添加用户 (用户名，密码)

### 设置防火墙，允许wan口访问ocserv端口。
  （让客户端可以连接ocserv服务。）
* 主用TCP，如果UDP可用，就用。
* 如果openwrt, 有LAN, <span style="background:#cfc">**有WAN**</span>。设置input规则,(2022-11测)
* 防火墙-> Traffic Rules
  * 添加
    ```
    协议: TCP+UDP
    Source zone: WAN
    Source address: 留空
    Source Port: 留空
    Destination zone: Device (input)
    Destination address: 留空
    Destination Port: 4443 (按需，多个端口空格隔开)
    Action: accept
    Restrict to address family: IPv4 only 或者 IPv4 and IPv6
    ```
* 如果openwrt只有LAN, <span style="background:#fcc">**无WAN**</span> (2024-09测)  
  因为LAN对于端口访问无限制，所以不用创建 Traffic Rules  

### 设置防火墙，允许openConnect客户端访问Lan/wan。
（客户端连接后，客户机的访问限制。）
* ocserv 没有加入 firewall ZONE 的设置。所以只能手动添加转发规则。
* 检查 `sysctl  net.ipv4.ip_forward` 应该显示 = 1  
  op中 ip_forward 默认就是 1。 所以不用管。
* 设置forward规则,(2022-11测)  
  防火墙-> Traffic Rules
  * 添加
    ```
    协议: Any
    Source zone: Any zone(forward)
    Source address: ocserv 的IP段，比如 192.168.100.0/24
    Destination zone: WAN 或 Any
       选Any,一条规则涵盖所有出口。或者添加多条规则,分别(按需)设置为WAN,LAN,wg0,
    Destination address: 留空
    Action: accept
    Restrict to address family: IPv4 only (按需)
    ```
* op默认有一条规则，对于已经建立的连接，返回的数据包是允许的。  
  会自动匹配，返回到目标地址192.168.100.0/24的转发。  
  所以，**不需要**专门配置，返回数据包的规则。  
* 如果op<span style="background:#cfc">**有WAN口**</span>,则已经有Masquerade规则。无需额外添加。(2022-11测)
* 如果op<span style="background:#fcc">**无WAN</span>,<span style="background:#cfc">有LAN**</span>,则需要手工添加IP伪装规则。(2024-09测)  
  防火墙-> NAT Rules  
  * 添加
    ```
    Name: 自己取名
    Restrict address family: Automatic(默认)/ipv4/ipv6，选自动,或按需
    Protocol: Any(默认) 或 按需
    Outbound zone: LAN
       如果还有其他出口需要IP伪装，则添加多条NAT规则，设定对应的Outbound zone
    Source address: ocserv 的IP段，比如 192.168.100.0/24
    Destination address: Any
    Action: MASQUERADE (IP伪装)
    其他选项卡的内容，全部用默认,不修改。
    ```
* 如果发现openconnect客户端还是**不能上网**，可能是dns解析失败。(immortalwrt24.10; 2025-08测)  
  检查 dnsmasq的配置，菜单位置 "网络 -> DHCP/DNS"。  
  对于 dnsmasq 和 dnsmasq-full 以下几项的位置不同，自己找找。  
  ```yaml
  - DNS 重定向: 默认勾上，DNS解析劫持。(通常这项不影响)
  - 重绑定保护(丢弃RFC1918地址): RFC1918就是内网地址。如果内网使用，去掉这个勾。
  - 仅本地服务: 默认勾上，但oc客户端通常不在lan网段，所以要去掉这个勾。
  ```

## 重新生成ocserv 的证书
* 仅用于 Openwrt-22.03
* 安装了 `ocserv`, 默认会安装`certtool`依赖包。如果没有`certtool`命令，则手动安装`opkg install certtool`。
* 如果删除 `rm /etc/ocserv/*.pem`, 然后 `/etc/init.d/ocserv restart` ,  
  所有证书，会重新生成一遍。不过, 除了有效时间变了，其他内容都没改变。  
* 在目录 `/etc/ocserv/pki/` 有两个文件，修改一下。**自定义证书内容**(按需)。  
  比如加一行 `organization = "xx"`，见【[Certtool's template file format](https://www.man7.org/linux/man-pages/man1/certtool.1.html#FILES)】
  ```
  ## pki/server.tmpl 中加入两行，用来匹配服务器IP或域名
  dns_name = "192.168.1.123"
  #ip_address = "192.168.1.123"
  ```
* 执行以下四行命令。重新生成证书，ECC或RSA证书，覆盖原来的。  
  ```bash
  ## 可以用 --bits 3072 指定 RSA私钥的长度，或者使用 --ecc 生成 secp256r1的 ECDSA私钥
  certtool --ecc --generate-privkey --outfile /etc/ocserv/ca-key.pem
  certtool --template /etc/ocserv/pki/ca.tmpl --generate-self-signed --load-privkey /etc/ocserv/ca-key.pem --outfile /etc/ocserv/ca.pem 
  certtool --ecc --generate-privkey --outfile /etc/ocserv/server-key.pem
  certtool --template /etc/ocserv/pki/server.tmpl --generate-certificate --load-privkey /etc/ocserv/server-key.pem --load-ca-certificate /etc/ocserv/ca.pem --load-ca-privkey /etc/ocserv/ca-key.pem --outfile /etc/ocserv/server-cert.pem 
  ## 查看证书
  certtool -i --load-certificate server-cert.pem
  ```
  * 用命令生成私钥`certtool --key-type XXX --generate-privkey --outfile server-key.pem`  
    `XXX`分别用`ecdsa ed25519 eddsa ed448 x25519 x448 gost01 gost12-256 gost12-512`代替。  
    ca 和 server 都使用 ecdsa 证书 (secp256r1)，<span style="background:#cfc">**连接正常**</span>，没有问题。  
    使用 eddsa(ed25519), ed25519, ed448, x25519, x448, gost01, gost12-256, gost12-512,服务能启动, 客户端连接时报错`服务器通信错误`。服务端报`No supported cipher suites have been found.`，<span style="background:#fcc">不支持</span>。(2025-08测)。
  * 用命令生成私钥`certtool --key-type ecdsa --curve secp256r1 --generate-privkey --outfile server-key.pem`  
    分别尝试`secp192r1 secp224r1 secp256r1 secp384r1 secp512r1`。  
    用secp192r1 secp224r1, 服务能启动，客户端连接时报错，<span style="background:#fcc">不支持</span>。  
    用secp256r1 secp384r1 secp512r1 工作正常，<span style="background:#cfc">**连接正常**</span>，没有问题。(2025-08测)。  
* 然后重启服务 `/etc/init.d/ocserv restart`  
* 以上的自签名证书`server-cert.pem`，无需转换格式，ios可以通过Safari导入ios系统中，但oc客户端连接时还是显示证书<span style="background:#fcc">不被信任</span>。  
ios的oc客户端，连接服务时，弹出警告"证书不被信任"，点击**查看详细**，就能**导入服务器证书**。导入后，下次连接就<span style="background:#cfc">不再弹出警告了</span> (证书IP或域名与实际相符)。  
* 也可以使用 Let's Encrypt 证书，不影响"用户证书认证"。参考【[使用 Let's Encrypt 在 Ubuntu 22.04 上设置 OpenConnect VPN 服务器 (ocserv)](https://cn.linux-terminal.com/?p=3472)】  
  oc客户端要使用域名连接，并且**域名要和证书匹配**。否则还是会警告,证书不被信任。  
  * 证书申请完成后，修改 `/etc/ocserv/ocserv.conf.template` 中  
    ```
    server-cert = /etc/letsencrypt/vpn.example.com/fullchain.pem
    server-key = /etc/letsencrypt/vpn.example.com/privkey.pem
    ```

## 用户证书认证
* 参考【[在 OpenConnect VPN 服务器 (ocserv) 中设置证书身份验证](https://cn.linux-terminal.com/?p=3423)】
* 让 ocserv 支持 密码 或 用户证书 认证。即，使用任意一种认证。(2025-08测，op24.10)
* OpenConnect -> Server Settings -> Edit Template 中  
  找到并修改  
  ```ini
  #auth = "certificate"   改为   enable-auth = "certificate"
  #ca-cert = /etc/ocserv/ca.pem    #去掉注释
  #cert-user-oid = 0.9.2342.19200300.100.1.1    #去掉注释。这项代表,用户名在证书的uid中
  #cert-user-oid = 2.5.4.3    #或者改为这一行,并去掉注释。这项代表,用户名在证书的cn中
  ```
  保存并提交。 
* 创建文件 `/etc/ocserv/pki/client.tmpl`，内容如下，按需修改，其中 `uid=` 的用户名必须存在与"用户密码"认证的配置中。  
  ```ini
  organization = "vpn.example.com"
  cn = "oc user2"
  # A user id of the certificate owner.
  uid = "user2"
  expiration_days = 3650
  tls_www_client
  signing_key
  encryption_key
  ```
* 在`/etc/ocserv` 目录中执行以下命令
  ```bash
  ## 继续使用原有的CA证书。 # 或者按上一节的方法，重新生成一个CA证书。
  # 创建用户私钥，如果使用rsa则去掉 --ecc，如需指定rsa私钥长度 --bits 4096
  certtool --generate-privkey --outfile client2-key.pem --ecc
  # 生成用户证书
  certtool --generate-certificate --load-privkey client2-key.pem --load-ca-certificate ca.pem --load-ca-privkey ca-key.pem --template pki/client.tmpl --outfile client2.pem
  # 打包为.p12文件
  certtool --to-p12 --load-privkey client2-key.pem --load-certificate client2.pem --pkcs-cipher aes-256 --outfile client2.p12 --outder
  # 为IOS打包.p12文件。ios不支持上一行的加密打包方式。
  certtool --to-p12 --load-privkey client2-key.pem --load-certificate client2.pem --pkcs-cipher 3des-pkcs12 --outfile ios-client2.p12 --outder
  ## 查看证书
  certtool -i --load-certificate client2.pem
  ```
* 把 `/etc/ocserv/client2.p12` 和 `/etc/ocserv/ios-client2.p12` 放在某个网站目录中，让用户下载导入。  
  用户证书使用 ecc证书 (secp256r1)，<span style="background:#cfc">**认证通过**</span>,没有问题。  
  * IOS中,用Safari打开url，证书导入ios系统是<span style="background:#fcc">无效的</span>，oc客户端中并不显示。  
    ios 的oc客户端中选择导入用户证书，只能从URL导入，必须是 `https://`，网站不能是自签名证书。  
    证书导入后，断开后,直接重连就<span style="background:#cfc">不用输入密码了</span>。(2025-08测)  
  * 其他客户端，没有测试。  



## 尝试用nginx反代到ocserv(失败)
* 认证部分，用到几个路径 `/`, `/auth`, `/+CSCOT+/`, `/CSCOSSLC/`,   
  可以成功反代。直到输入完 账号,密码。然后说证书不对。  
* 把nginx的server证书，copy一份给 ocserv共用。  
  证书就对了，继续之后，握手连接失败。  
  发现进入了专用协议。没法反向代理了。  
* 放弃。

## 使用 haproxy做端口复用
* 安装 haproxy，使用 TCP模式，根据 sni分流，让 nginx的https 和 ocserv共用端口。  
  见本贴的后面 【[ubuntu](#ubuntu)】 的配置。

-----

# Debian
2023-10记录
## 安装配置
* 使用的系统为，  
  debian-11 (bullseye).  
  debian-12 (bookworm).  
* 安装 `apt install ocserv`  
  * 卸载 `apt purge ocserv; apt autoremove; 然后删除 /etc/ocserv/ 目录`
* 装好，ocserv 默认就已经启动。deb-11  
  ocserv 默认启动，但启动失败，因为没配置证书。deb-12  
  配置文件在 `/etc/ocserv/ocserv.conf`  
* 默认设置
  * 使用端口 tcp/443 和 udp/443，
  * 支持多种认证方式。
    ```ini
    ## auth directives. Available options: certificate, plain, pam, radius, gssapi.
    #auth = "pam"    #用pam认证
    #auth = "pam[gid-min=1000]"      #使用系统用户
    #auth = "plain[passwd=./sample.passwd,otp=./sample.otp]"   #使用密码文件＋ 一次性密码
    auth = "plain[passwd=./sample.passwd]"       #使用密码文件,用ocpasswd命令创建密码文件
    #auth = "certificate"      #使用证书认证
    #auth = "radius[config=/etc/radiusclient/radiusclient.conf,groupconfig=true]"   #使用radius认证
    ```
    deb11 默认是 `auth = "pam[gid-min=1000]"`  
    deb12 默认是 `auth = "plain[passwd=/etc/ocserv/passwd]"`  
  * IP, DNS, 路由。  
    默认 `ipv4-network = 192.168.1.0`  
    默认 `dns = 192.168.1.1` **建议测试一下,如果配错IP,对后面调试影响很大**  
    默认 `route = 192.168.0.0/16`  
* ### 修改配置文件 /etc/ocserv/ocserv.conf
  ```ini
  tcp-port = 443  #工作端口，默认443，按需更改
  udp-port = 443
  auth = "plain[passwd=/etc/ocserv/passwd.ocs]"   #使用密码文件
  #以下三行证书配置，是deb11 默认设置。
  #以下三行证书配置，deb12, 默认 没有配置，所以启动失败。
  server-cert = /etc/ssl/certs/ssl-cert-snakeoil.pem
  server-key = /etc/ssl/private/ssl-cert-snakeoil.key
  ca-cert = /etc/ssl/certs/ca-certificates.crt
  ipv4-network = 192.168.100.0   #分配给客户端的IP段
  ipv4-netmask = 255.255.255.0
  dns = 192.168.1.1     #推送给客户端的dns
  route = default       #客户端设置默认网关，所有流量走这个连接
  no-route = 192.168.2.0/24  #按需，客户端,这个网段的流量不走这个连接
  banner = "Welcome MyHost"  #按需。不写这行,认证后没有提示直接OK。
  ```
* 然后，创建密码文件，创建用户和密码，`ocpasswd -c /etc/ocserv/passwd.ocs  usename`
* 可以自己创建/申请 ca 和 server 证书，替换默认证书。  
  自己创建证书可以用 certtool命令，来自`apt install gnutls-bin`包。  
  见上文 OpenWRT 的配置中，重新生成证书，RSA证书。  
  或见下文 CentOS8 的配置中，自己创建证书(自签名)，ECC证书。  
* 最后重启 ocserv 生效。  
  `service ocserv restart`
* 检查 `net.ipv4.ip_forward = 1` 打开**内核转发**。
* 检查防火墙规则，**允许转发**，
  ```bash
  # 如果FORWARD 规则链的 policy accept, 有没有这两条规则都不影响转发。
  # 如果FORWARD 规则链的 policy drop, 就必须添加这两条规则。
  #使用 iptables
  iptables -I FORWARD -s 192.168.100.0/24 -j ACCEPT
  iptables -I FORWARD -d 192.168.100.0/24 -j ACCEPT
  #使用 nft （policy accept, 有没有这两条规则都不影响转发)
  #在chain xx{ type filter hook forward priority filter; policy drop(或accept); } 中，加入，
  ip daddr 192.168.100.0/24 counter accept
  ip saddr 192.168.100.0/24 counter accept
  #或者，用openwrt那样的两条规则，替换上面两条，
  ct state established,related accept
  ip saddr 192.168.100.0/24 counter accept
  ```
  至此，oc客户端(192.168.100.x)发出的数据包，就能转发出去。但因为对方没有对应的路由规则，返回包,回不来 (表现为网络不通)。
* 配置 **IP伪装(MASQUERADE)**。  
  如果，出口网卡是固定IP，用 SNAT规则,性能更好。  
  假设，你的出口网卡设备为 "eth0"，使用 eth0 上的IP 做伪装。  
  即，配置NAT(网络地址转换)规则，把从192.168.100.x发出的数据包，转换为,以eth0的IP发出。  
  ```bash
  #使用 iptables
  iptables -t nat -I POSTROUTING -s 192.168.100.0/24 -o eth0 -j MASQUERADE
  #使用 nft
  #在chain xx{ type nat hook postrouting priority srcnat; policy accept; }中，加入，
  oifname "eth0" ip saddr 192.168.100.0/24 counter masquerade
  ```
* 配置完成。oc客户端连上后，就可以从 eth0 向外访问了。

## nft防火墙规则
* 特殊情况下(有docker)的**FORWARD规则**
* 使用 nft rule，如果有2个相同的 hook，policy分别是 accept和drop。  
  写入 policy accept 中的 accept rule，就不起作用了。必须要写入到 policy drop的 chain中。  
* nft rule，如果多个相同的hook，policy 都是 accept，写入的 drop rule，好像也会有问题。
* 我测试的时候，debian上装了docker，docker生成了一堆规则(iptables)。  
  其中docker的 FORWARD chain 的 policy 是drop。  
  所以只能用，  
  ```bash
  iptables -I FORWARD -s 192.168.100.0/24 -j ACCEPT
  iptables -I FORWARD -d 192.168.100.0/24 -j ACCEPT
  ```
  另建nft chain，总是无效，
  ```
  chain forward {  #这里的规则总是匹配不到
     type filter hook forward priority -5;
     ip daddr 192.168.100.0/24 counter accept
     ip saddr 192.168.100.0/24 counter accept
  }
  ```
* 这两条iptables 的 forward 规则，
  * 使用 iptables.service 在开机时导入。(未测试)
  * 使用 /etc/rc.local 写入。(未测试)
  * 考虑在docker启动后，再插入。  
    参考【[使用systemd将iptables规则在docker启动后自动导入](https://www.cnblogs.com/wiseo/p/15000745.html)】

## pve的LXC container
* ocserv 需要使用 tun 设备。
* LXC 中的 debian，实际使用的是 pve的内核，无法加载kmod (tun.ko)，所以没有 /dev/net/tun 设备。  
  LXC中，虽然能配置 ocserv，能运行。但客户端登陆时，因找不到 tun设备而<span style="background:#fcc">连接失败</span>。
* 放弃。

-----

# CentOS8
2023-10记录
## 安装配置
* 安装 `yum install ocserv`
  * 卸载 `yum remove ocserv; yum autoremove; 然后删除 /etc/ocserv/ 目录`
* 装好，ocserv 默认没启动。也没激活。  
  配置文件在 `/etc/ocserv/ocserv.conf`
* 修改 `ocserv.conf` 配置文件，  
  ```ini
  tcp-port = 443  #工作端口，默认443
  udp-port = 443
  server-cert = /etc/pki/ocserv/public/server.crt
  server-key = /etc/pki/ocserv/private/server.key
  ca-cert = /etc/pki/ocserv/cacerts/ca.crt
  auth = "plain[passwd=/etc/ocserv/passwd.ocs]"  #默认 auth ="pam"
  ipv4-network = 192.168.100.0/24  #默认没配置，分配给客户端的IP段
  dns = 192.168.1.1   #默认没配置，推送给客户端的dns, **建议测试一下,如果配错IP,对后面调试影响很大**
  route = default   #默认没配置，推送给客户端的route
  no-route = 192.168.2.0/24  #按需，推送给客户端的排除route
  banner = "Welcome MyHost"  #按需
  ```
* 然后，创建密码文件，创建用户和密码，`ocpasswd -c /etc/ocserv/passwd.ocs  usename`
* `service ocserv start`直接启动。第一次启动，会**自动执行** ocserv-genkey 生成所需的证书。
* 如果对证书**不满意**，自己创建证书(自签名)，ECC证书，用 certtool命令，来自`yum install gnutls-utils`包。
  ```bash
  cd /etc/pki/ocserv/
  cat <<EOF > ca.tmpl  #ca证书模板,按需修改前两行
  cn = "Your CA name"
  organization = "Your fancy name"
  serial = 1
  expiration_days = 3650
  ca
  signing_key
  cert_signing_key
  crl_signing_key
  EOF
  certtool --generate-privkey --key-type ecdsa --bits 256 --outfile ca-key.pem  #生成ca密钥
  certtool --generate-self-signed --load-privkey ca-key.pem --template ca.tmpl --outfile ca-cert.pem  #自签名ca证书
  cat <<EOF > server.tmpl  #服务证书模板,按需修改前两行
  cn = "Your hostname or IP"
  organization = "Your fancy name"
  expiration_days = 3650
  signing_key
  encryption_key
  tls_www_server
  EOF
  certtool --generate-privkey --key-type ecdsa --bits 256 --outfile server-key.pem  #生成server密钥
  certtool --generate-certificate --load-privkey server-key.pem --load-ca-certificate ca-cert.pem --load-ca-privkey ca-key.pem --template server.tmpl --outfile server-cert.pem  #server证书
  mv ca-key.pem private/ca.key   #移到正确位置。如果没有,ocserv会自己重新生成
  mv ca-cert.pem cacerts/ca.crt
  mv server-key.pem private/server.key  #移到正确位置。如果没有,ocserv会自己重新生成
  mv server-cert.pem public/server.crt
  ```
* 防火墙，**开放ocserv端口**。
  ```bash
  firewall-cmd --zone=public --add-port=443/tcp
  firewall-cmd --zone=public --add-port=443/udp
  firewall-cmd --zone=public --add-port=443/tcp --permanent
  firewall-cmd --zone=public --add-port=443/udp --permanent
  ```
* 检查 `net.ipv4.ip_forward = 1` 打开**内核转发**。
* 检查防火墙规则，**允许转发**，  
  通常是允许的。可以不用配置。  
  ```bash
  #可能用这个命令# firewall-cmd --zone <Zone Name> --add-forward  #没测试
  ```
* 配置 **IP伪装(MASQUERADE)**。
  ```bash
  firewall-cmd --list-all-zones  #查看所有的zone，确定出口网卡在哪个zone
  firewall-cmd --zone public --add-masquerade  #通常在public zone
  firewall-cmd --zone public --add-masquerade --permanent #系统重启也有效
  ```
* 激活服务，启动服务。
  ```
  systemctl enable ocserv   #激活
  systemctl restart ocserv  #重启
  ```
* Centos8, 安装的haproxy-1.8.27 , 开启 haproxy的log记录，见【[在centos8 配置haproxy日志功能](https://www.codeleading.com/article/25454976137/)】,【[Haproxy之日志打印](https://www.cnblogs.com/sandyflower/p/17462936.html)】  
  需要在 chroot目录中创建log文件，`/var/lib/haproxy/dev/log`  
  或者，开启 rsyslog的 514/UDP.  
  否则 haproxy 无法发送log到 rsyslog 中。  



# ubuntu
* 安装,配置方法与debian相同
## openwrt 作为客户端,连接Ubuntu的 ocserv
* 发现每 41-56分钟，连接会断开又马上重连。  
  Ubuntu的 ocserv.conf 中, 默认为 idle-timeout = 1200  
* 在openwrt中，增加一个定时任务，每30分钟ping一下对端。  
  发现还是 50-56分钟断开一次。  
* 在openwrt中，定时任务，每20分钟ping一下对端。  
  连接不再断开。  
* 改 idle-timeout = 3610  
  openwrt 不ping (删掉定时任务)，连接每2小时断开一次。  
  openwrt 每小时ping一下，连接不再断开。  
* 改 idle-timeout = 1810  
  openwrt 半小时ping一下，连接不再断开。  
* 客户端换immortalWrt24，报错，(2025-08)  
  ```
  /lib/netifd/vpnc-script: line 120: can't create /tmp/dnsmasq.d/openconnect.vpn-ocs0: nonexistent directory
  Failed to open /dev/vhost-net: No such file or directory
  DTLS handshake failed: Resource temporarily unavailable, try again. (每分钟一次)
  ```
  网络原因 udp不通，导致handshake失败，在服务端 ocserv.conf 注释掉 `udp-port=`  
  immWrt24中`luci-proto-openconnect`缺少内核依赖包，安装`kmod-vhost-net`解决。  
  新版dnsmasq-full修改了目录名，dnsmasq.d找不到，暂时无法解决。  
* 配置openconnect客户端时，  
  * 填写 "VPN 服务器证书的 SHA1 哈希值" 以下任意一种格式都可以,
    * `certtool --fingerprint --load_certificate server-cert.pem` 得到 "证书指纹SHA1"
    * `openssl x509 -in server-cert.pem -noout -fingerprint` 去掉冒号得到 "证书指纹SHA1"
    * 参考【[官网的说明](https://openwrt.org/docs/guide-user/services/vpn/openconnect/client#key_management)】使用SHA256 hash  
      `openssl x509 -in server-cert.pem -pubkey -noout | openssl pkey -pubin -outform der |openssl dgst -sha256 -binary |openssl enc -base64`  
      格式为: "pin-sha256:abcd1234567"  
  * 或者，不填写 "VPN 服务器证书的 SHA1 哈希值", 填写 "CA 证书"
## 使用haproxy做端口复用
* 【[immortalwrt上的haproxy配置参考](https://www.cnblogs.com/osnosn/p/12388465.html#haproxy)】
* 在Ubuntu,安装`apt install stunnel4`
* 配置stunnel
  * 使用 certtool 创建服务器证书。见【[这里](https://www.cnblogs.com/osnosn/p/12388465.html#3proxy)】
  * 创建配置文件，【[stunnel 官方文档](https://www.stunnel.org/docs.html)】  
    `cp /usr/share/doc/stunnel4/examples/stunnel.conf-sample /etc/stunnel/stunnel.conf`  
  * 修改配置文件 /etc/stunnel/stunel.conf，保留全局设置，
    ```
    setuid = stunnel4
    setgid = stunnel4
    pid = /var/run/stunnel4/stunnel.pid
    output = /var/log/stunnel4/stunnel.log
    ```
  * 去掉例子中原来的 client和server设置，添加以下server设置。  
    给ssh套上SSL。给mysql也套一层SSL。  
    ```
    [ssh]
    client = no
    accept  = 127.0.0.1:10022
    connect = 127.0.0.1:22
    cert = /etc/ssl/stunnel/server-cert.pem
    key  = /etc/ssl/stunnel/server-key.pem
    [mysql]    # mysql自己就有ssl，前面再套ssl，效率是低了，但能用
    client = no
    accept  = 127.0.0.1:13306
    connect = 127.0.0.1:3306
    cert = /etc/ssl/stunnel/server-cert.pem
    key  = /etc/ssl/stunnel/server-key.pem
    ```
* 在Ubuntu,修改nginx的ssl配置，监听端口改到 2443，让出443口，给haproxy用。  
  并加上 proxy-protocol 的相关配置，见【[这里的nginx的配置](https://www.cnblogs.com/osnosn/p/12388465.html#haproxy)】  
* 在Ubuntu,修改 ocserv配置，其他的配置不改动，只找以下三项，并修改。  
  ```
  listen-host = 127.0.0.2  #改本地监听
  tcp-port =1443     #改端口
  listen-proxy-proto = true  #接受 proxy-protocol
  ```
* 在Ubuntu,安装`apt install haproxy` 【[文档2.0.33](https://docs.haproxy.org/2.0/configuration.html)】
* 配置 haproxy，按sni域名分流  
  ```
  ... #保留原有的 global和 defaults配置。timeout的默认的单位是 ms, 默认值是50s
  frontend tls_tcp
     bind :443
     mode tcp
     option   tcplog
     tcp-request inspect-delay 5s
     tcp-request content accept if { req.ssl_hello_type 1 }
     use_backend ocserv       if { req.ssl_sni -i ocs.myxxxx.com }
     use_backend ssh-tls       if { req.ssl_sni -i ssh.myxxxx.com }
     use_backend mysql-tls   if { req.ssl_sni -i sql.myxxxx.com }
     use_backend nginx         if { req.ssl_sni -i www.myxxxx.com }
     default_backend nginx
  backend ocserv
     mode tcp
     server ocserv 127.0.0.2:1443 check-ssl check-send-proxy send-proxy-v2
     timeout tunnel 1810s    #配合ocserv的idle-timeout
  backend ssh-tls
     mode tcp
     # stunnel 不支持,不接受 proxy-protocol
     # ssh看到的来源IP是来自stunnel的IP，无法通过来源IP做访问控制。
     server ssh 127.0.0.1:10022 check-ssl
  backend mysql-tls
     mode tcp
     # mysql自己就有ssl/tls，前面再套一层ssl/tls，效率降低，但能用。
     # mysqld显示来源IP为stunnel所在的IP，导致无法通过来源IP做访问控制。
     server mysql 127.0.0.1:13306 check-ssl
  backend nginx
     mode tcp
     server nginx 127.0.0.1:2443 check-ssl check-send-proxy send-proxy-v2
     #tcp-request content reject   #拒绝连接/直接断开连接
  ```
* stunnel不支持proxy-protocol, 可以考虑用 gost替代, gost支持 proxy-protocol。  
  不过 ssh, mysqld 都不支持 proxy-protocol, 所以最终的服务还是无法获取来源IP。  
  * 可以在ssh, mysqld前面套一个go-mmproxy, 或者 haproxy的 tcp转发,配置 usesrc clientip解决。  
    【[ssh前置haproxy或go-mmproxy获取真实来源IP](https://www.cnblogs.com/osnosn/p/11781359.html#ssh%E5%89%8D%E7%BD%AEhaproxy%E6%88%96go-mmproxy%E8%8E%B7%E5%8F%96%E7%9C%9F%E5%AE%9E%E6%9D%A5%E6%BA%90ip)】(2026-08测)  
* 检查是否有错误 `haproxy -f /etc/haproxy/haproxy.cfg -c`
* 重启 haproxy服务，使之生效。
* 因为 ocserv本身就有ssl，就无法用 haproxy的SSL Termination(SSL终止)，让haproxy接管ssl部分。  
  再说，haproxy的TCP模式也无法做SSL终止。SSL终止似乎只能用于mode http。  
  所以，以上配置使用SSL-Pass-Through(SSL穿透/透传)。  

### immortalWrt24 上的openconnect客户端
* 在openwrt中的 ocs客户端无法指定sni的域名。有两个办法解决。任意一个办法都可以。
  * 修改 /etc/hosts 增加一行或多行，ip在前域名在后，空格分隔。如 `192.168.100.22  ocs.myxxxx.com`  
    有的版本的openwrt，重启后 hosts的内容会丢失。  
  * 网络 -> DHCP/DNS -> DNS记录 -> 主机名映射，把域名/IP 添加在这里。  
    然后重启dnsmasq， `/etc/init.d/dnsmasq restrat`  
* 网络 -> 接口 -> ocs0, 修改 "VPN服务器" 为 "ocs.myxxxx.com:443"
* 重启 ocs 网络接口，openconnect就连上去了。

### pymysql 连接套了 ssl/tls的mysql
```
# 从各大搜索引擎搜索，都搜不到例程。询问各种AI给出的例程，全都是错的，AI都在一本正经的瞎说。
# PyMySQL-0.9.3， Python-3.8.10，通过查看源码+测试，2025-10测试通过
# PyMySQL-1.1.1， Python-3.7.5，2025-10测试通过
import pymysql
import ssl
import socket
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.check_hostname = False    #不验证域名
ssl_context.verify_mode=ssl.CERT_NONE   #不验证证书
sni_host='sql.myxxxx.com'      #SNI 域名
db=pymysql.connect(user='root',passwd='123456',db='dbname',use_unicode=True,defer_connect=True)

ssocket = ssl_context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=sni_host)
ssocket.connect(('192.168.100.22', 443))
db.connect(sock=ssocket)
#或者
#ssocket = ssl_context.wrap_socket(socket.create_connection(('192.168.100.22',443)), server_hostname=sni_host)
#db.connect(sock=ssocket)

#cur=db.cursor()
#cur.execute(sql)
#db.commit()
#cur.close()

db.close()
print('show ssocket closed or not:', ssocket)
```



# 参考
* 【[openconnect/ocserv](https://github.com/openconnect/ocserv)】
* 【[openconnect/recipes](https://gitlab.com/openconnect/recipes)】
* 【[ocserv-configuration-basic](https://gitlab.com/openconnect/recipes/-/blob/master/ocserv-configuration-basic.md)】
* 【[Debian下搭建Ocserv(openconnect server),并启用证书验证](https://moonagic.com/posts/setup-ocserv-on-debian/)】
* 【[在Debian 10 Buster上设置OpenConnect VPN服务器（ocserv）](https://www.mmcloud.com/4805.html)】
* 【[Debian下安装配置Ocserv搭建Cisco Anyconnect的开源服务端](https://aenes.com/post/716.html)】



----end----

-----
**转载注明来源: 本文链接 https://github.com/osnosn/HowTo/blob/master/Linux/openwrt-22.03_debian_centos_ocserv_haproxy_stunnel.md**

----
