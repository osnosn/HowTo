## [OpenWrt: Config 802.1X,EAP-PEAP,EAP-TLS using FreeRadius3 on Newifi-mini](https://github.com/osnosn/HowTo/blob/master/OpenWRT/Newifi-mini_OpenWrt_EAP-PEAP_EAP-TLS_And_FreeRadius3.md)

Written in 2019-07-15.

I'm using: OpenWrt-18.06.4   
firmware file: http://downloads.openwrt.org/releases/18.06.4/targets/ramips/mt7620/openwrt-18.06.4-ramips-mt7620-y1-squashfs-sysupgrade.bin

**ssh to router, execute command and modify config file in shell mode.**
```
## ssh to router, run in shell mode
opkg update (Get newest list)
opkg remove wpad-mini
opkg install wpad  (Support WPA2-EAP,WPA2 802.1x on openwrt's wifi) 
```
> Router space usage: overlay used:10%,free 10.9M 

```
## ssh to router, run in shell mode, install freeradius3
opkg install freeradius3 freeradius3-mod-eap-peap freeradius3-mod-always freeradius3-mod-realm freeradius3-mod-expr freeradius3-mod-files freeradius3-mod-eap-mschapv2
```
> Router space usage: overlay used:27%,free:8.8M

> freeradius3-mod-eap-peap (peap)   
> freeradius3-mod-always (reject)   
> freeradius3-mod-realm (suffix)   
> freeradius3-mod-expr (expression)   
> freeradius3-mod-files (user & password)   
> freeradius3-mod-eap-mschapv2 (peap needed)   

### modify `/etc/freeradius3/mods-config/files/authorize` 
Add one or more line, like this：    
`bob     Cleartext-Password := "hello" `

### modify `/etc/freeradius3/mods-enabled/eap`   
```
- default_eap_type = md5  
+ default_eap_type = peap 
comment out lines about: md5 {..}  leap {..} gtc {...} tls {..} ttls{...} 
- dh_file = ${certdir}/dh
+ #dh_file = ${certdir}/dh

- #check_crl = yes
+ check_crl = yes
```

### Create CA & server CERTs for test，Or [Create CERTs for EAP-TLS using openssl](https://github.com/osnosn/HowTo/blob/master/OpenSSL/Create_CERTs_for_EAP-TLS_using_openssl.md)
```
## ssh to router, run in shell mode
opkg install openssl-util
```
> Router space usage: overlay used:29%,free:8.6M

```
## ssh to router, run in shell mode. if no such directory, create it.
cd /etc/freeradius3/certs/

## create CA
openssl ecparam -name prime256v1 -out ec_param
openssl req -nodes -newkey ec:ec_param -days 3650 -x509 -sha256 -keyout ecca.key -out ecca.crt

## create server CERT. server CERT must use RSA, otherwise radius will fail to authorize.  
## I guess: if use ECC in server CERT, maybe need "dh_file=". I don't known.
openssl req -nodes -newkey rsa:1024 -days 3650 -sha256 -keyout serverec.key -out serverec.csr
## commonName: field Must be SET
mkdir ./demoCA/
mkdir ./demoCA/newcerts
touch ./demoCA/index.txt
echo 01 > ./demoCA/serial
openssl ca -extensions v3_ca -days 3650 -out serverec.crt -in serverec.csr -cert ecca.crt -keyfile ecca.key
## view cert：openssl x509 -in serverec.crt -noout -text

## create crl.pem
openssl ca -gencrl -keyfile ecca.key -cert ecca.cert -out crl.pem -config openssl.cnf

cat serverec.key serverec.crt > server.pem
cat ecca.crt crl.pem > ca.pem
## If only config EAP-PEAP, no need "crl.pem", no need "check_crl = yes". just "cat ecca.crt > ca.pem".
```

### Run "radiusd -X" according to error msg(red color) shows filename & line number. comment it out.
<img src="https://github.com/osnosn/HowTo/raw/master/OpenWRT/images/openwrt-radius1.png" width="400" />

according to `radiusd -X` error msg, I was comment out this lines: 
```
modify /etc/freeradius3/sites-enabled/default
comment out this lines.
(In section: authenticate{..} ) 
Auth-Type PAP {
    pap
}
Auth-Type CHAP {
    chap
}
digest

(In section: authorize{..} ) 
preprocess
chap
digest
expiration
logintime
pap

(In section: preacct {...} )
preprocess

(In section: accounting {...} )
detail
unix
exec
attr_filter.accounting_response

(In section: post-auth {...} )
exec

(In section: post-auth {Post-Auth-Type REJECT{...}..} )
attr_filter.access_reject
```
```
modify /etc/freeradius3/sites-enabled/inner-tunnel
comment out this lines.
(In section: authenticate{..} ) 
Auth-Type PAP {
    pap
}
Auth-Type CHAP {
    chap
}

(In section: authorize{..} ) 
chap
expiration
logintime
pap

(In section: session{..} ) 
radutmp

(In section: post-auth {Post-Auth-Type REJECT{...}..}  )
attr_filter.access_reject
```
> Router space usage: overlay used:29%,free:8.5M

### modify /etc/freeradius3/clients.conf
```
modify section: client localhost {...} , "secret = testing123", or add a section.
client localnet {
    ipaddr = 192.168.0.0/16
    secret = testing123  (Radius-Authentication-Secret)
}

```

### test peap-mschapv2:
`opkg install eapol-test `
> Router space usage: overlay used:32%,free:8.2M

Write file: test-peap
```
network={
        ssid="example"
        key_mgmt=WPA-EAP
        eap=PEAP
        identity="bob"
        anonymous_identity="anonymous"
        password="hello"
        phase2="autheap=MSCHAPV2"
   # if uncomment line below，test failue in openwrt shell mode. but test OK in CentOS.
   # I guess eapol_test in openwrt is not full version. Maybe eapol-test-openssl better, I'm not try.
   #   ca_cert="/etc/freeradius3/certs/ca.pem"
}
```
```
## in shell mode, run
eapol_test -c test-peap -s testing123
## or 
eapol_test -c test-peap -a 127.0.0.1 -s testing123
## or 
eapol_test -c test-peap -a 127.0.0.1 -p 1812 -s testing123
```
"testing123" is secret in file /etc/freeradius3/clients.conf   
**If see "SUCCESS" in last line, then test OK.**   
logout from ssh. all done.   
### config WIFI, start radiusd service
In openwrt luci web page，enable & start radiusd service.   
<img src="https://github.com/osnosn/HowTo/raw/master/OpenWRT/images/openwrt-radius3.png" width="300" />   
Or "S50radiusd" file in directory "/etc/rc.d/" is enabled.   
<img src="https://github.com/osnosn/HowTo/raw/master/OpenWRT/images/openwrt-radius5.png" width="300" />   
In 2.4G & 5G WiFi configuration, in "Wireless Security"   
set  "Encryption" to "WPA2-EAP", "Cipher" to "AES"    
set "Radius-Authentication-Server" to "127.0.0.1", "Radius-Authentication-Port" to "1812",   
set "Radius-Authentication-Secret" to "testing123".   
<img src="https://github.com/osnosn/HowTo/raw/master/OpenWRT/images/openwrt-radius4.png" width="300" />   
Provides to the Phones, computers, laptops, that support "enterprise Authentication".   
set one or more user&password in file "/etc/freeradius3/mods-config/files/authorize"   
家里人用一个，或者用证书登陆。其他人,用另外的账号，万一泄露，修改密码不影响家人设备联网。   

Normally, you need another 2.4G WiFi, add a new SSID,   
set "wireless encryption" to "WPA2-PSK", "Algorithm" to "AES", and set "secret key".   
Use for devices, that not support "enterprise Authentication".   
比如"远程遥控插座"，"扫地机器人"，……   

> **有大神说碰到[如下情况](https://www.right.com.cn/FORUM/forum.php?mod=viewthread&tid=259345)，我没碰到。但也写在这留作参考。**   
> **我没修改这行，测试就通过了。**   
> 如果失败原因是 “The users session was previously rejected” ，   
> 而且往上翻日志翻来覆去就是找不出原因，请尝试：   
> 在 /etc/freeradius3/sites-available/inner-tunnel 中，`MS-CHAP`改为`MSCHAP`, 第 220 行附近，有一段配置项：   
> ```
> - Auth-Type MS-CHAP {   
>      mschap   
>   }   
> + Auth-Type MSCHAP {   
>      mschap   
>   }
> ```

---------------

## config EAP-TLS support
Because eapol_test fail in openwrt with CERTs.   
I change to CentOS for test using eapol_test.  
```
## in openwrt's shell mode
opkg update
opkg install freeradius3-mod-eap-tls
```
### modify /etc/freeradius3/mods-enabled/eap
```
## uncomment tls {...} ,
- #tls {
- #   tls = tls-common
- #}
+ tls {
+    tls = tls-common
+ }

- #check_crl = yes
+ check_crl = yes
```
stop service   
`/etc/init.d/radiusd  stop `   
test run  
`radiusd -X `   
if no error message, then press `CTRL-C` to stop test.   
start service   
`/etc/init.d/radiusd start `   

### Create users CERTs for test，Or [Create CERTs for EAP-TLS using openssl](https://github.com/osnosn/HowTo/blob/master/OpenSSL/Create_CERTs_for_EAP-TLS_using_openssl.md)
```
## in openwrt's shell mode
cd /etc/freeradius3/certs/

## create user CERT
openssl req -nodes -newkey ec:ec_param -days 3650 -sha256 -keyout userec.key -out userec.csr
## commonName: field must be set
openssl ca -extensions v3_ca -days 3650 -out userec.crt -in userec.csr -cert ecca.crt -keyfile ecca.key
```
> Router space usage: overlay used:32%,free:8.2M    
> <img src="https://github.com/osnosn/HowTo/raw/master/OpenWRT/images/openwrt-radius2.png" width="400" />   

you need generate crl.pem file using openssl, then   
`cat ecca.crt  crl.pem > ca.pem `   
and uncomment "check_crl = yes" in file "/etc/freeradius3/mods-enabled/eap".
```
- #check_crl = yes
+ check_crl = yes
```
> I found that Win10 will fail to use EAP-TLS certificate authentication.   
> The error message of radiusd shows that the User-Name contains spaces and refuses to authenticate.  
> It was found that Win10 enforced the use of the "CN=" content of the user certificate as the User-Name.  
> Two solutions:   
>    - When creating user certificates, do not include spaces in the `CN` value.    
>    - Or install `freeradius3-mod-attr-filter` to filter out the spaces in the User-Name before validation.

### eapol_test 
* reference：[freeradius测试](http://www.voidcn.com/article/p-uflkqryr-er.html)  

write file "test-tls"   
```
network={
    eap=TLS
    eapol_flags=0
    key_mgmt=IEEE8021X
    identity="test"
    password="test123"

    ca_cert="/etc/freeradius3/certs/ca.pem"
    client_cert="/etc/freeradius3/certs/userec.crt"
    private_key="/etc/freeradius3/certs/userec.key"
    #private_key_passwd="whatever"
}
```
run in CentOS's shell mode ` eapol_test -c test-tls -a <your radius/router IP> -s 'testing123' `   
you will see "SUCCEED", it means every thing goes OK. 

-----
reference:   
* freeradius3的web luci配置页面，没搞。[可以参考这里](https://github.com/MuJJus/luci-app-radius)。      
* 另有一篇讲[openwrt上freeradius2的EAP-TLS配置](https://github.com/ouaibe/howto/blob/master/OpenWRT/802.1xOnOpenWRTUsingFreeRadius.md)，参考价值不高。他把所有radius包都装上了。   
* 参考:[FreeRadius EAP-TLS configuration](https://wiki.alpinelinux.org/wiki/FreeRadius_EAP-TLS_configuration#.2Fetc.2Fraddb.2Fclients.conf)   

------------
This is my config files.   
`cat /etc/freeradius3/sites-enabled/default  |sed '/^$/d'|sed '/[\t]*#/d' `
```
server default {
listen {
        type = auth
        ipaddr = *
        port = 0
        limit {
              max_connections = 16
              lifetime = 0
              idle_timeout = 30
        }
}
listen {
        ipaddr = *
        port = 0
        type = acct
        limit {
        }
}
listen {
        type = auth
        port = 0
        limit {
              max_connections = 16
              lifetime = 0
              idle_timeout = 30
        }
}
listen {
        ipv6addr = ::
        port = 0
        type = acct
        limit {
        }
}
authorize {
        filter_username
        mschap
        suffix
        eap {
                ok = return
        }
        files
        -sql
        -ldap
}
authenticate {
        Auth-Type MS-CHAP {
                mschap
        }
        eap
}
preacct {
        acct_unique
        suffix
        files
}
accounting {
        -sql
}
session {
}
post-auth {
        update {
                &reply: += &session-state:
        }
        -sql
        remove_reply_message_if_eap
        Post-Auth-Type REJECT {
                -sql
                eap
                remove_reply_message_if_eap
        }
}
pre-proxy {
}
post-proxy {
        eap
}
}
```
`cat /etc/freeradius3/sites-enabled/inner-tunnel  |sed '/^$/d'|sed '/[\t]*#/d' `
```
server inner-tunnel {
listen {
       ipaddr = 127.0.0.1
       port = 18120
       type = auth
}
authorize {
        filter_username
        mschap
        suffix
        update control {
                &Proxy-To-Realm := LOCAL
        }
        eap {
                ok = return
        }
        files
        -sql
        -ldap
}
authenticate {
        Auth-Type MS-CHAP {
                mschap
        }
        eap
}
session {
}
post-auth {
        -sql
        Post-Auth-Type REJECT {
                -sql
                update outer.session-state {
                        &Module-Failure-Message := &request:Module-Failure-Message
                }
        }
}
pre-proxy {
}
post-proxy {
        eap
}
```
`cat /etc/freeradius3/mods-enabled/eap  |sed '/^$/d'|sed '/[\t]*#/d' `
```
eap {
        default_eap_type = peap
        timer_expire     = 60
        ignore_unknown_eap_types = no
        cisco_accounting_username_bug = no
        max_sessions = ${max_requests}
        tls-config tls-common {
                private_key_password = whatever
                private_key_file = ${certdir}/server.pem
                certificate_file = ${certdir}/server.pem
                ca_file = ${cadir}/ca.pem
                ca_path = ${cadir}
                cipher_list = "DEFAULT"
                ecdh_curve = "prime256v1"
                cache {
                        enable = yes
                        max_entries = 255
                }
                verify {
                }
                ocsp {
                        enable = no
                        override_cert_url = yes
                        url = "http://127.0.0.1/ocsp/"
                }
        }
        tls {
                tls = tls-common
        }
        peap {
                tls = tls-common
                default_eap_type = mschapv2
                copy_request_to_tunnel = no
                use_tunneled_reply = no
                virtual_server = "inner-tunnel"
        }
        mschapv2 {
        }
}
```
`cat /etc/freeradius3/mods-config/files/authorize |sed '/^$/d'|sed '/[\t]*#/d' `
```
bob     Cleartext-Password := "hello"
test    Cleartext-Password := "test123"
DEFAULT Framed-Protocol == PPP
        Framed-Protocol = PPP,
        Framed-Compression = Van-Jacobson-TCP-IP
DEFAULT Hint == "CSLIP"
        Framed-Protocol = SLIP,
        Framed-Compression = Van-Jacobson-TCP-IP
DEFAULT Hint == "SLIP"
        Framed-Protocol = SLIP
```
`cat /etc/freeradius3/clients.conf |sed '/^$/d'|sed '/[\t]*#/d' `
```
client localhost {
        ipaddr = 127.0.0.1
        proto = *
        secret = testing123
        require_message_authenticator = no
        limit {
                max_connections = 16
                lifetime = 0
                idle_timeout = 30
        }
}
client localhost_ipv6 {
        ipv6addr        = ::1
        secret          = testing123
}
client 192.168.1.0/24 {
        ipaddr = 192.168.1.0/24
        secret = testing123
}
```

------------
References:   
[openwrt 编译newifi 应用程序](https://www.cnblogs.com/diylab/p/6021432.html),    
[Newifi-mini OpenWrt 下 EAP-PEAP,EAP-TLS 企业级无线认证及 FreeRadius3](https://www.cnblogs.com/osnosn/p/11186646.html)   

----
