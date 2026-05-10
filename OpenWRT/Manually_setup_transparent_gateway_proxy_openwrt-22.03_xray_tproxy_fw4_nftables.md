# [手工设置透明网关代理_openwrt-22.03_xray_tproxy_fw4_nftables](https://github.com/osnosn/HowTo/blob/master/OpenWRT/Manually_setup_transparent_gateway_proxy_openwrt-22.03_xray_tproxy_fw4_nftables.md)
**转载注明来源: [本文链接](https://github.com/osnosn/HowTo/blob/master/OpenWRT/Manually_setup_transparent_gateway_proxy_openwrt-22.03_xray_tproxy_fw4_nftables.md)**，写于 2025-04-25.

# 系统环境
* openwrt-22.03 , 使用 fw4 , 即 nftables
* openwrt-23.05 , 使用 fw4 ; 策略路由和防火墙规则设置 和 op-22.03 相同。

## xray 配置
* 参考【[透明代理（TProxy）配置](https://xtls.github.io/document/level-2/tproxy.html)】
* 没有配置dns走xray
* routing 中要设置 udp/123直连，用于ntp对时协议不走xray。如果是用本地局域网ntp服务，或防火墙规则中有相关设置，则跳过这项。
* freedom 的出站设置 domainStrategy 为 UseIP，以避免直连时因为使用本机的 DNS 出现一些奇怪问题；
* 要在所有的 outbound 加一个 mark=18，即mark=0x12，这个 mark 与下文 防火墙规则 配合，以直连 xray 发出的流量（blackhole 不用配置 mark）。
  ```json
  {
    "inbounds": [
      {   //在inbounds 中加入这一节 "dokodemo-door"
        "tag": "tproxy-in",
        "listen": "127.0.0.1",
        "port": 12345,
        "protocol": "dokodemo-door",
        "settings": {
          "network": "tcp,udp",
          "followRedirect": true
        },
        "sniffing": {  //开启snifing，否则路由无法匹配域名
          "enabled": true,
          "destOverride": ["http", "tls", "quic"]
        },
        "streamSettings": {
          "sockopt": { "tproxy": "tproxy" }
        }
      },
      ... 其他配置
    ],
    "outbounds": [
      //每一个outbounds的出口中，除了blackhole，包含 "mark":18 参数
      //  "streamSettings": {
      //    "sockopt": { "mark": 18 }   // 0x12, xray配置中只能写整数
      //  }
      {
        "tag": "direct",
        "protocol": "freedom",
        "settings": { "domainStrategy": "UseIP" },
        "streamSettings": {
          "sockopt": { "mark": 18 }   // 0x12
        }
      },
      ... 其他配置
    ],
    "routing": {
      ... 其他配置
      "rules": [
        {    //ntp对时协议
          "type": "field",
          "inboundTag": ["tproxy-in"],
          "port": 123,
          "network": "udp",
          "outboundTag": "direct"
        },
        ... 其他配置
      ]
    }
  }
  ```

## 策略路由
* 方法1 (可用)，把这两句，写入 /etc/rc.local 中，  
  或通过 web配置页面，System->Startup->Local Startup , 其实就是 /etc/rc.local  
  ```bash
  # 设置策略路由, 仅ipv4,
  # 添加路由表 100，指向local的loopback
  ip route add local 0.0.0.0/0 dev lo table 100
  # 所有标记 0x10 的Packet走路由表100
  ip rule add fwmark 0x10 table 100
  ```
* 方法2 (更好, 推荐)，用luci的 web页面配置
  * 添加路由表 100，指向 local 的 loopback  
    在web配置页面，Network->Routing->Static IPv4 Routes 添加一条，  
	```
	General Settings
	  Interface: loopback
	  Route type: local  #默认unicast, 要改为local
	  Target: 0.0.0.0/0
	  Gateway: 留空
	Advanced Settings
	  Table: 100
	  其他: 留空或不修改
	```
  * 所有标记 0x10 的Packet走路由表100  
    在web配置页面，Network->Routing->IPv4 Rules 添加一条，  
	```
	General Settings
	  Priority: 30000  #自选，1-32765 都可以，
	  Route type: unicast  #默认值
	  Table: 100
	  其他: 留空或不修改
	Advanced Settings
	  Firewall mark:  0x10  #图 3中的 1应该写0x10,(图片未修改)
	  Invert match: 不勾 #默认值
	  其他: 留空或不修改
	```

<img src="https://github.com/osnosn/HowTo/raw/master/OpenWRT/images/tproxy_routing1.png" style="width:200px;border:1px solid #000" /> <img src="https://github.com/osnosn/HowTo/raw/master/OpenWRT/images/tproxy_routing2.png" style="width:200px;border:1px solid #000" /> <img src="https://github.com/osnosn/HowTo/raw/master/OpenWRT/images/tproxy_routing3.png" style="width:200px;border:1px solid #000" />


## 防火墙规则
* 需要安装 nft-tproxy 的内核支持，  
  `opkg update && opkg install kmod-nft-tproxy`
* 添加自定义规则，文档参考【[Firewall configuration /etc/config/firewall -> Includes (22.03 and later with fw4)](https://openwrt.org/docs/guide-user/firewall/firewall_configuration#includes_2203_and_later_with_fw4)】  
  下面，选取了其中一种方式。
* 创建文件 `/etc/nftables.d/20-xray-rules.nft` 内容如下, 仅ipv4,  
  文件名只要是 `.nft`结尾就行，文件名随便。  
  ```
  define RESERVED_IP = {
        10.0.0.0/8,
        100.64.0.0/10,
        127.0.0.0/8,
        169.254.0.0/16,
        172.16.0.0/12,
        192.0.0.0/24,
        224.0.0.0/4,
        240.0.0.0/4,
        255.255.255.255/32
  }
  define LAN_IP = {
        192.168.10.0/24,
        192.168.20.0/24
  }
  chain mangle_xray_prerouting {
        type filter hook prerouting priority mangle; policy accept;
        ip saddr != $LAN_IP return
        ip daddr $RESERVED_IP return
        #ip daddr 192.168.0.0/16 tcp dport != 53 return  #由代理接管DNS解析
        #ip daddr 192.168.0.0/16 udp dport != 53 return  #由代理接管DNS解析
        ip daddr 192.168.0.0/16 return    #代理不接管DNS解析
        meta nfproto ipv4 udp dport { 123 } return  #ntp对时,直通。有这一行就不用写xray规则。
        ip protocol { tcp,udp } tproxy ip to 127.0.0.1:12345 meta mark set 0x10  #匹配ip rule规则的fwmark
  }
  chain mangle_xray_output {
        type route hook output priority mangle; policy accept;
        ip daddr $RESERVED_IP return
        #ip daddr 192.168.0.0/16 tcp dport != 53 return  #由代理接管DNS解析
        #ip daddr 192.168.0.0/16 udp dport != 53 return  #由代理接管DNS解析
        ip daddr 192.168.0.0/16 return    #代理不接管DNS解析
        meta nfproto ipv4 udp dport { 123 } return  #ntp对时,直通。有这一行就不用写xray规则。
        meta mark 0x12 return   #匹配xray中outbounds的mark
        ip protocol { tcp,udp } meta mark set 0x10  #匹配ip rule规则的fwmark
  }
  # 或者用 $LAN_IP 替换所有的 192.168.0.0/16 也可以。
  ```
* 在 openwrt的命令行中，执行 `fw4 reload` 如果没有任何输出，则OK，(没有报错)。
* 如果此openwrt作为主路由，prerouting 链中的规则 `ip saddr != $LAN_IP return`，是防止 WAN 口中同网段的其它人将网关填写成你的 WAN_IP，从而蹭你的透明网关代理用，还可能带来一定的危险性。如果op不是主路由,可以不要这条规则。
  * 其实就是限制哪些内网网段，可以使用这个透明网关代理。
* 防火墙规则，没有配置 ipv6，
* 防火墙规则，支持openwrt本机，和lan口下其他机器的透明网关代理。
* 内核包kmod-nft-socket，没有用到就没装。如果添加的规则中用到才需要安装。

## 手工设置完成
* **重启 openwrt，配置不丢失，策略路由和防火墙规则自动生效。**
* 其他方式，
  * 策略路由和防火墙规则，也可以通过自定义服务的方式，实现开机启动。  
    自定义一个服务脚本，比如: /etc/init.d/my-tproxy.sh  
    启动顺序要在 network服务之后，比如: START=90  
    把 策略路由和防火墙规则，写在这个服务脚本中。  
    脚本的编写，比较麻烦。也需要更多的知识。  
    参考: 【[Openwrt-sing-box Tproxy代理折腾](https://www.right.com.cn/forum/thread-8387992-1-1.html)】  

## immortalwrt24再次配置
* 网络环境。(文中op指的是immortalwrt24) (2025-08测)
  * op做旁路由，只有一个网口LAN
  * openConnect拨入，客户端ip与LAN口不同网段。见【[ocserv配置](https://www.cnblogs.com/osnosn/p/16923645.html)】
* 配置好，**加入**策略路由，但**没加入**防火墙规则时。  
  oc客户端可以通过op上网，仅IP访问，域名不行。  
  **检查了dnsmasq的配置后**("仅本地服务"的选项)，解决dns解析的限制问题，域名访问就OK了。  
* **加入**防火墙规则后，op本身可以通过tproxy上网(代理的log有显示)。但oc客户端不能访问,除{$RESERVED_IP,$LAN_IP}之外的网页。  
  op本身和oc客户端的域名解析有时不行，重启整个op后就没问题了。可能是防火墙规则,修改/reload多次,导致的问题。  
  oc客户端的{$RESERVED_IP,$LAN_IP}网页访问OK，走的直通。  
  oc客户端的其他网页访问 既不走tproxy(代理的log无显示)，也不直通。就是无法访问。  
  imm24默认支持fullCone NAT,尝试关掉这项也不解决。  
  op本机traceroute baidu.com, udp包会进入tproxy, 导致没有显示。  
  oc客户端显示的traceroute baidu.com, 是直通的, 没有进入tproxy，能正常trace到目标IP。  
  从oc客户端发起TCP连接到 baidu.com:80，卡住，不显示连接成功，若干秒后超时断开。  
  最终，发现这句没写对`ip route add local 0.0.0.0/0 dev lo table 100` local 错选为unicast。  
  更正后，测试正常。  
  连接lan口的,与LAN口同网段的其他机器, op本身, oc客户端, 都能通过tproxy上网。  


------
# 其他方法 tun2socks5
heiher/hev-socks5-tunnel 的性能比较好。

* 【[零基础学会TUN与socks5互转，支持TCP、UDP](https://linux.do/t/topic/444662/4)】【[heiher/hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel)】
* 【[heiher/hev-socks5-tproxy](https://github.com/heiher/hev-socks5-tproxy)】
* 【[使用tun2socks进行全局网络代理](https://vitsumoc.github.io/%E4%BD%BF%E7%94%A8tun2socks%E8%BF%9B%E8%A1%8C%E5%85%A8%E5%B1%80%E7%BD%91%E7%BB%9C%E4%BB%A3%E7%90%86.html)】【[xjasonlyu/tun2socks](https://github.com/xjasonlyu/tun2socks)】
* 【[tun2proxy -SOCKS5等代理转换为TUN口](https://songxwn.com/tun2proxy/)】【[tun2proxy/tun2proxy](https://github.com/tun2proxy/tun2proxy)】



----end----

-----
**转载注明来源: 本文链接 https://github.com/osnosn/HowTo/blob/master/OpenWRT/Manually_setup_transparent_gateway_proxy_openwrt-22.03_xray_tproxy_fw4_nftables.md**

----
