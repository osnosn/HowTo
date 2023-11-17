## [Create CERTs for PEAP/EAP-TLS using OpenSSL](https://github.com/osnosn/HowTo/blob/master/OpenSSL/Create_CERTs_for_PEAP_EAP-TLS_using_openssl.md)
## [用openssl为PEAP/EAP-TLS生成证书（CA证书,服务器证书,用户证书）](https://www.cnblogs.com/osnosn/p/10597897.html)
写于: 2019-03-27.   

> 本文参考了大神的文章:   
> 　[搭建一个「最安全」的Wi-Fi网络](https://zhuanlan.zhihu.com/p/28927420)，[楠站](https://zenandidi.com/archives/948)，

本文是为
* [CentOS7用hostapd做radius服务器为WiFi提供802.1X企业认证](https://github.com/osnosn/HowTo/blob/master/Linux/CentOS7_hostapd_radius_WIFI_802.1x_EAP-PEAP_EAP-TLS_EnterpriseAuthentication.md)
* [Newifi-mini OpenWrt 下 EAP-PEAP,EAP-TLS 企业级无线认证及 FreeRadius3](https://github.com/osnosn/HowTo/blob/master/OpenWRT/Newifi-mini_OpenWrt_EAP-PEAP_EAP-TLS_And_FreeRadius3.md)

WiFi的EAP-TLS认证,准备证书。   
如果想为WEB服务器生成自签名证书,我补充了一篇笔记: **"[用openssl为WEB服务器生成证书](https://github.com/osnosn/HowTo/blob/master/OpenSSL/Create_CERTs_for_WebeServer_using_openssl.md)"**。   

我用的是openssl-1.0.2k.    
脚本支持生成RSA，ECC证书。   运行时带参数指定类型。   
脚本压缩包: 【[ssl_create-cert-for-hostapd_v0.5.7z](https://github.com/osnosn/HowTo/raw/master/OpenSSL/ssl_create-cert-for-hostapd_v0.5.7z)】

-->开始。按以下路径建立文件，脚本。   
```
ssl_create-cert/   <-- 这个目录, 自己随便取名
   |_  2db/0serial
   |_  2db/2indexdb.txt
   |_  3certs_new/
   |_  4export/
   |_  clear_all_cert.sh
   |_  copy-pem-to.sh
   |_  create-crl.sh
   |_  new-ca.sh
   |_  new-server.sh
   |_  new-user.sh
   |_  revoke-user.sh
   |_  user_certs/
   |_  openssl.cnf
   |_  README
 ```
`mkdir 2db` 创建目录。
`echo "2233AA1234" > 2db/0serial` 证书序列号，自己随便编，十六进制数。

`cat /dev/null > 2db/2indexdb.txt`  
> 此文件必须是0字节，否则openssl会报错  
> `wrong number of fields on line 1 (looking for field 6, got 1, '' left)`  

`mkdir  3certs_new  4export  user_certs`

clear_all_cert.sh
```
#!/bin/sh
# clear_all_cert.sh
if [  "$#" -ne 1  -o  "$1" != "clearall" ]; then
        echo "Usage: $0 clearall"
        echo "     Clear all the \"keys\" and \"certs\"."
        echo "     It will remove *.pem"
        echo "     It will remove 3certs_new/* 4export/* user_certs/*"
        echo "     It will remove ALL!!!!!"
        exit 1
fi
if [ -f ca_key.pem ]; then
        rm -f ca_key.pem ca_cert.pem ca_cert.txt
fi
if [ -f crl.pem ]; then
        rm -f crl.pem ca_cert+crl.pem
fi
if [ -f server_key.pem ]; then
        rm -f server_key.pem server_cert.pem
fi
if [ -d user_certs ]; then
        rm -f user_certs/*
fi
if [ -d 3certs_new ]; then
        rm -f 3certs_new/*
fi
if [ -d 4export ]; then
        rm -f 4export/*
fi
if [ -f 2db/0serial ]; then
        rm -f 2db/0serial.old
fi
if [ -f 2db/2indexdb.txt ]; then
        cat /dev/null > 2db/2indexdb.txt
        rm -f 2db/2indexdb.txt.attr 2db/2indexdb.txt.attr.old 2db/2indexdb.txt.old
fi
echo "  ALL cert files removed."
echo "You may now run ./new-ca.sh to get start"
echo ""
```

copy-pem-to.sh
```
#!/bin/sh
# copy-pem-to.sh
DIR=$1
if [  "$#" -ne 1  -o  "${#DIR}" -le "1" ]; then
        echo "Usage: $0 dest_directory"
        echo "     $0  ./"
        echo "     $0  a/"
        exit 1
fi
if [ ! -d $DIR ]; then
        echo " \"$DIR\" directory not found. Exit."
        exit 1
fi

echo "copy \"ca_cert+crl.pem\" \"server_cert.pem\" \"server_key.pem\" to \"$DIR\""
cp -i ca_cert+crl.pem $DIR
cp -i server_cert.pem $DIR
cp -i server_key.pem  $DIR
```

create-crl.sh
```
#!/bin/sh
#./create-crl.sh

if [ ! -f ca_key.pem ]; then
        echo "CA not found. Exit."
        exit
fi
if [ -f crl.pem ]; then
        echo "CRL file found. Exit."
        exit
fi
openssl ca -gencrl -keyfile ca_key.pem -cert ca_cert.pem -out crl.pem -config openssl.cnf && \
cat ca_cert.pem crl.pem > ca_cert+crl.pem
echo "copy file \"server_cert.pem\" \"server_key.pem\" \"ca_cert+crl.pem\" to hostapd dir."
echo "And start service \"hostapd\"."

echo ""
```

new-ca.sh
```
#!/bin/sh
# new-ca.sh
# Create the master CA key and cert. This should be done once.
if [ -f ca_key.pem ]; then
        echo "Root CA key found. Exit."
        exit
fi
keytype=""
case "$1" in
   "rsa2048")
      keytype="rsa:2048"
      ;;
   "rsa4096")
      keytype="rsa:4096"
      ;;
   "ec256")
      keytype="ec:ec_param"
      openssl ecparam -name prime256v1 -out ec_param
      ;;
   "ec384")
      keytype="ec:ec_param"
      openssl ecparam -name secp384r1 -out ec_param
      ;;
   *)
      echo
      echo "Usage: $0  {rsa2048|rsa4096|ec256|ec384}"
      echo
      exit
      ;;
esac

exportdir="4export"

echo "Self-sign the root CA..."
echo "No Root CA key found. Generating one"
openssl req -x509 -nodes -days 36500 -newkey ${keytype} -keyout ca_key.pem -out ca_cert.pem -new -sha512 -config openssl.cnf -extensions v3_ca -utf8 -subj "/C=CN/ST=广东/L=gz/O=Home/CN=Wifi EAP Root CA/"  && \
openssl x509 -outform der -in ca_cert.pem -out ./${exportdir}/CA.crt  && \
openssl x509 -in ca_cert.pem -noout -text -nameopt utf8 > ca_cert.txt
echo "You may now run ./new-server.sh"
echo ""
```

new-server.sh
```
#!/bin/sh
# new-server.sh
# Create the server key and cert. 
if [ -f server_key.pem ]; then
        echo "Server key found. Exit."
        exit
fi
keytype=""
case "$1" in
   "rsa2048")
      keytype="rsa:2048"
      ;;
   "rsa4096")
      keytype="rsa:4096"
      ;;
   "ec256")
      keytype="ec:ec_param"
      openssl ecparam -name prime256v1 -out ec_param
      ;;
   "ec384")
      keytype="ec:ec_param"
      openssl ecparam -name secp384r1 -out ec_param
      ;;
   *)
      echo
      echo "Usage: $0  {rsa2048|rsa4096|ec256|ec384}"
      echo
      echo "   ECC or RSA are both OK. ECC 或 RSA 都可以。"
      echo
      echo "   When use ECC server cert, Android8 got \"no shared cipher\"."
      echo "   USE \"RSA\" cert on server side if use OLD android system."
      echo "   如果使用ECC证书，安卓8系统协商加密算法会失败。"
      echo "   如果用旧安卓系统，建议服务器证书使用\"RSA\"。"
      echo
      exit
      ;;
esac

echo "Create server ssl for hostapd."
echo "No Server key found. Generating one."

openssl req -nodes -new -newkey ${keytype} -keyout server_key.pem -out server_csr.pem -config openssl.cnf -utf8 -subj "/C=CN/ST=广东/L=gz/O=Home/CN=WiFi Radius Server/"  && \
openssl ca -days 36500 -in server_csr.pem -out server_cert.pem -config openssl.cnf -extensions server_cert -batch  && \
rm -rf server_csr.pem
echo "You may now run ./create-crl.sh"
echo ""
```

new-user.sh
```
#!/bin/sh
# new-user.sh
# Create the user key and cert. This should be done once per cert.
if [ $# -lt 3 ]; then
   echo
   echo "Usage: $0  {rsa1024|rsa2048|rsa4096|ec256|ec384}  userName  days [pass]"
   echo "   days between 2 and 365"
   echo
   exit 1
fi
CERT=$2
if [ -f user_certs/user_${CERT}_key.pem ]; then
        echo "user_certs/user_${CERT}_key.pem found. Exit."
        exit 0
fi
keytype=""
case "$1" in
   "rsa1024")
      keytype="rsa:1024"
      ;;
   "rsa2048")
      keytype="rsa:2048"
      ;;
   "rsa4096")
      keytype="rsa:4096"
      ;;
   "ec256")
      keytype="ec:ec_param"
      openssl ecparam -name prime256v1 -out ec_param
      ;;
   "ec384")
      keytype="ec:ec_param"
      openssl ecparam -name secp384r1 -out ec_param
      ;;
   *)
      echo
      echo "Usage: $0  {rsa1024|rsa2048|rsa4096|ec256|ec384}  userName  days [pass]"
      echo "   days between 2 and 365"
      echo
      exit
      ;;
esac

DAYS=${3:-1}  # default 1
if [ "${DAYS}" -gt 365 -o "${DAYS}" -lt 2 ]; then
   if [ "${DAYS}" -ne 36500 ];then
      echo
      echo "Usage: $0  {rsa1024|rsa2048|rsa4096|ec256|ec384}  userName  days [pass]"
      echo "   days between 2 and 365"
      echo
      exit 1
   fi
fi

PASS=${4:-123}  # default 123

exportdir="4export"

export RANDFILE=2db/.random_state
## win10连接EAP-TLS时强制使用用户证书的"CN="作为用户名。建议"CN="不要包含空格。
## freeradius3不允许用户名中包含空格。用hostapd做radius时用户名无此限制。
openssl req -nodes -new -newkey ${keytype} -keyout user_certs/user_${CERT}_key.pem -out user_certs/user_${CERT}_csr.pem -config openssl.cnf -utf8 -subj "/C=CN/ST=广东/L=gz/O=Home/CN=WiFi-${CERT}/" && \
openssl ca -days ${DAYS} -in user_certs/user_${CERT}_csr.pem -out user_certs/user_${CERT}_cert.pem -config openssl.cnf -extensions user_cert -batch && \
rm -rf user_certs/user_${CERT}_csr.pem && \
echo -e "Export certs...\n \"Export Password\" MUST set for IOS.\n \"Export Password\" MAY empty for Android,windows."  && \
openssl pkcs12 -export -out ./${exportdir}/${CERT}.p12 -inkey user_certs/user_${CERT}_key.pem -in user_certs/user_${CERT}_cert.pem -certfile ca_cert.pem -caname "Wifi EAP RootCA" -name "${CERT}-wifi-user" -passout pass:${PASS}
# 友好名称 "-name" "-caname" windows不支持utf8中文的友好名称

echo ""
```

revoke-user.sh
```
#!/bin/sh
# revoke-user.sh
CERT=$1
if [ $# -ne 1 ]; then
        echo "Usage: $0 userName"
        exit 1
fi
if [ ! -f user_certs/user_${CERT}_key.pem ]; then
        echo "user_certs/user_${CERT}_key.pem NOT found. Exit."
        exit 0
fi

openssl ca -revoke user_certs/user_${CERT}_cert.pem -config openssl.cnf && \
openssl ca -gencrl -keyfile ca_key.pem -cert ca_cert.pem -out crl.pem -config openssl.cnf && \
cat ca_cert.pem crl.pem > ca_cert+crl.pem
echo "You NEED update \"ca_cert_crl.pem\" file and restart service \"hostapd\"."


echo ""
```

`chmod  +x  clear_all_cert.sh  new-ca.sh  new-server.sh  create-crl.sh  copy-pem-to.sh  new-user.sh  revoke-user.sh`

openssl.cnf   
此文件2023-10更新. 对应 v0.5.7z 压缩包。   
```
#openssl.cnf
[ ca ]
default_ca = hostapd

[ hostapd ]
dir = .
serial = $dir/2db/0serial
database = $dir/2db/2indexdb.txt
new_certs_dir = $dir/3certs_new
certificate = $dir/ca_cert.pem
private_key = $dir/ca_key.pem
RANDFILE = $dir/2db/.random_state

default_bits = 4096
default_days = 36500
default_crl_days = 36500
default_md = sha512
#unique_subject = no

policy = policy_anything

[ policy_anything ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = supplied
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ req ]
distinguished_name = req_distinguished_name
string_mask = utf8only
[ req_distinguished_name ]

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical,CA:true
certificatePolicies=ia5org,@pl_section
[ server_cert ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:false
extendedKeyUsage = serverAuth,msSGC,nsSGC
#extendedKeyUsage = 1.3.6.1.5.5.7.3.1,msSGC,nsSGC  #这种写法，和上面那行的效果一样
certificatePolicies=ia5org,@pl_section
subjectAltName = @dns_names
[ dns_names ]
DNS.1 = xx.mydomain.xx   #要配置一个域名,非真实的域名也行
DNS.2 = mydomain         #只写一个名称也行
[ user_cert ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:false
#subjectAltName = email:copy
extendedKeyUsage = clientAuth,emailProtection,timeStamping
certificatePolicies=ia5org,@pl_section  #可加",@pl_section2",不过没必要

[ pl_section ]
policyIdentifier = "X509v3 Any Policy"
# 颁发者说明的链接. windows中,要导入信任之后才生效.
CPS.1 = https://your.web.com/cps/readme.html
userNotice.1=@pl_notice
[ pl_notice ]
# 颁发者说明,Issuer statment. (没找到换行的表示方法)
explicitText="Read deail at https://your.web.com/xxx.html"
#explicitText="UTF8:请看这里 https://your.web.com/xxx.html"  #utf8,中文
[ pl_section2 ]
#这行，会加入一项: Policy: TLS Web Server Authentication
policyIdentifier = "1.3.6.1.5.5.7.3.1"
```
> userNotice.1 的文字说明，中文要加上UTF8，否则只能是英文。  
> 文字说明，无论此证书是否被系统信任，查看证书时都会出现在"颁发者说明"中(Issuer Statement)。  
> CPS.1 的链接。系统未信任此证书时，是不显示的。信任后，才会出现在"颁发者说明"中(Issuer Statement)。  
> CPS.1= 可以是 "http://" 也可以是 "https://"。   
> <img src="https://github.com/osnosn/HowTo/raw/master/OpenSSL/images/EAP-TLS1.png" width="200" /><img src="https://github.com/osnosn/HowTo/raw/master/OpenSSL/images/EAP-TLS2.png" width="200" /><img src="https://github.com/osnosn/HowTo/raw/master/OpenSSL/images/EAP-TLS3.png" width="200" />
 openssl.cnf 格式参考 `man x509v3_config`，【[x509v3_config](https://github.com/eZioPan/Learning_Linux/blob/markdown/86.1.1%E3%80%81x509v3%20%E9%85%8D%E7%BD%AE%E6%96%87%E4%BB%B6.adoc)】。  

README
```
README
create by osnosn, 2019-03-20. version_0.2.
--------------
To clear all:
   ./clear_all_cert.sh

Certs for hostapd:
   modify C/ST/L/O/CN in new-ca.sh,new-server.sh,newuser.sh, 可以使用中文。
   modify openssl.cnf:
      CPS.1=
      explicitText=
   keytype: rsa2048, rsa4096, ec256, ec384.
   ./new-ca.sh
   ./new-server.sh
   ./create-crl.sh
  copy file "server_cert.pem" "server_key.pem" "ca_cert+crl.pem" to hostapd dir.
   ./copy-pem-to.sh
  And start service "hostapd".

Certs for user:
   ./new-user.sh

Revoke user:  
   ./revoke-user.sh  
  After revoke, replace file "ca_cert+crl.pem" and reload "hostapd".   
  
--------------
server cert: ECC会导致Android-8连接失败, 错误为"no shared cipher"。  
  如有旧设备，建议server cert用RSA证书。Android12用 ECC server证书没问题。  
  ca, user cert 可以用ECC。  
user cert in "user_certs/" and "4export/"   
import "4export/xxx.p12" to  android,ios,windows client.   
用户证书 xxx.p12 在 "4export/" 目录中，   
一个p12文件包含ca证书,user证书,user密钥三个内容。   
android,windows可以一次导入三个内容。  
ios会丢弃ca。  

ios导入密钥强制输入加密密码(密码不能为空)。   
android,windows导入密钥可以接受空密码。   

windows 必须导入"当前用户"，否则连接wifi时不能识别证书。   
windows连接EAP-TLS: 点击搜索到的wifi ssid，出现输入"用户","密码"时，点击"用证书认证"(证书导入当前用户后)。   

---------
```

`chmod  +x  clear_all_cert.sh  new-ca.sh  new-server.sh  create-crl.sh  copy-pem-to.sh  new-user.sh  revoke-user.sh`

给android导入用户证书一定要用p12格式，不能用pem格式。   
Android不认pem格式中的密钥，只认公钥。导致没密钥不能用于连接WIFI。   
导入CA证书，因为是公钥，可以用pem格式。  

使用方法:
>  修改 C=/ST=/L=/O=/CN= 的内容合适你自己。这些项可以使用中文。  
>  修改 openssl.cnf 中 CPS.1= 和 explicitText= 。  
>  在IOS，windows中可以看到，可以写漂亮点。主要是CN=写漂亮点。会显示为证书名。  
> Android没地方看证书描述。写啥，Android都看不到。  
>  ./clear_all_cert.sh clearall  
> ./new-ca.sh  ec256  
> ./new-server.sh  rsa2048    #有旧安卓设备连接,服务器证书建议用RSA。安卓12用ECC没问题.  
> ./create-crl.sh   
> ./copy-pem-to.sh  hostapd_conf_dir/  
> service restart hostapd  
> ./new-user.sh  ec256  user1  36500   
> ./new-user.sh  ec256  user2  36500   
> copy xx.p12 file from "4export/" 目录，分发给用户。   


## 其他证书测试
* 用 freessl.cn申请的TrustAsia 一年期免费ECC证书，3月期ECC证书，3月期RSA证书，  
  用 buyPass.com 的6月期RSA证书，  
  用于hostapd做<span style="background:#cfc">**PEAP认证都是OK**</span>的。   
  但,无法做EAP-TLS认证，因为不拥有CA证书 (无ca.key)，无法签发用户证书。   
  国内的 Android12 手机客户端，测试ok，  
  另一台 Android12 (T-Mobile REVVL V+ 5G, WTRVL5G)，测试ok，  
  选择:  
  - EAP方法: PEAP;   
  - 阶段2身份验证: MSCHAPV2;   
  - CA证书: 使用系统证书;   
  - 在线证书状态: 不验证;   
  - 域名: 输入服务器证书的域名;   
  - 输入正确的用户/密码。   
  - 匿名身份:建议填用户名, 或留空,或随便填。   
  
  <span style="background:#cfc">**成功登录WiFi**</span>。安卓手机<span style="background:#cfc">**无需另外导入CA证书**</span>。   
  如果域名输入错误，hostapd报`internal error`，不能登录WiFi。   
  可以考虑使用 acme.sh 脚本，自动更新证书。   
  (2023-10测ok)   
* 申请LetsEncrypt的3个月期RSA证书，3个月期ECC证书。   
  用于hostapd做PEAP认证，hostapd都报`certificate expired`。Android手机<span style="background:#fcc">无法登录WiFi</span>。   
  可能是运行hostapd的系统太旧了，系统内置的ca是2018-04月的，太旧。   
  印象中LetsEncrypt在2021年有"过期"的问题。   
  换个系统op22.03，系统内置ca是2021-10月的，测试报`certificate expired`，失败。  
  升级op22的ca，更新到2023-03月，测试还是报`certificate expired`。  
  也许与手机的内置CA有关。  
  可是把这个证书部署在https网站上，用相同的手机访问，浏览器没有证书警告。  
  看来 LetsEncrypt的证书，不能用于peap认证。(2023-10测)  
  - 见【[LetsEncrypt证书信任链](https://letsencrypt.org/zh-cn/certificates/)】,【[给Let's Encrypt证书过期的移动设备安装证书](https://www.bilibili.com/read/cv13897062/)】   
* 有的手机升级到 安卓11或以上，   
  比如 Android12 (T-Mobile REVVL V+ 5G, WTRVL5G)，  
  登录wifi时，`CA证书/CA certificate`取消了 "不验证" 的选项。只能选择:   
  - `使用系统证书/Use system certificates` (网上申请的服务器证书,用这个选项)   
  - `安装证书/Install certificates` (导入自签名CA证书,用这个选项)   

  只有`在线证书状态/Online Certificate Status`(即:OCSP验证) 有"不验证"的选项。   
  并且必须要填写`域名/Domain`。   
  所以，制作自签名证书，需要加上 `subjectAltName =` 项目。   
  制作的服务器证书，subjectAltName中如有多个DNS名称(可以是FQDN,可以是仅主机名)。   
  安卓手机登录时，域名输入任意一个 (DNS内容) 即可。(比如，有 `DNS.2=wifi`，域名输入wifi即可)   
  能<span style="background:#cfc">**成功登录WiFi**</span>。   
  如果域名输入错误，hostapd报`internal error`，不能登录WiFi。  
  手机登录wifi前，<span style="background:#cfc">**必须要导入CA自签名证书**</span>。否则,hostapd报 `unknow CA`，不能登录WiFi。   
  &emsp;安卓手机导入证书的路径，  
  * 设置->安全->更多安全->加密与凭据->安装证书，选择安装"CA"或"(WLAN)证书"  
  * Settings->Security&Location->Advanced->Encryption&credentials->Install a certificate, 选择"CA"或"WiFi"。  

  测试PEAP<span style="background:#cfc">**登录OK**</span>。以下是证书导入要求，(2023-10测ok)  
  * 把 ca.pem 导入到 `信任的凭据(信任的CA证书)/Trusted credentials`-> `用户证书/user` 中。否则, 报 `unknown ca`。  
  * 把 ca.pem 导入到 `用户凭据/User credentials` 中，用途为 WIFI/WLAN。否则, 连接WiFi时无法选择ca。  

  测试EAP-TLS方式 <span style="background:#cfc">**登录OK**</span>。以下是证书导入要求，(2023-10测ok)  
  * 把 ca.pem 导入到 `信任的凭据(信任的CA证书)/Trusted credentials`-> `用户证书/user` 中。否则, 报 `unknown ca`。  
  * 把包含(ca证书,用户证书,用户key)的 p12 导入到 `用户凭据/User credentials` 中，用途为 WIFI/WLAN。否则, 连接WiFi时无法选择ca，无法选择用户证书。  
* 下载到安卓手机的自签名CA证书，文件名中要包含cert字样(如xxx-cert.pem)。   
  否则,有的安卓(某牌子Android-12)不认，无法安装。   
  导入CA时选择用于wifi。或者在登录WiFi时，在"CA证书"项,选择"安装证书"。   
  <span style="background:#cfc">**ECC和RSA**</span> 的CA证书，安卓都能识别，支持导入。(2023-10测ok)   
  有的手机，没有上述限制。只要是后缀为 .crt 或 .p12 就能被识别为证书。  
  (2023-10测ok)  
* 对于以前的部署，如果server证书没有DNS。无需重做全套证书。   
可以<span style="background:#cfc">**保留**</span>原来的CA和用户证书。用原CA,重做server证书，加上DNS项就行。(2023-10测ok)   
  - 修改 openssl.cnf 中 DNS项。   
  - 删除/改名,原server证书的文件名。   
  - 修改 new-server.sh 中 `CN=`的内容，与原来的稍有不同就行。   
  - 执行 `./new-server.sh ` 生成新的server证书。   

  更换server证书后，所有原来能成功连接的设备，  
  * 安卓，之前选择 CA不验证的，不受影响。能自动连上，无需人工干预。  
  * iPad(ios16)，iphone(ios14)，已经连接上的，用一段时间，或者重新首次连接WiFi，会弹证书框，需要点击一次"信任"，才能连上。  
  * win10，重新首次连接WiFi，需要重新确认一次。  
* 对于iPad (ios16)，登录PEAP，只能选择"自动"，没有地方填写"域名"。   
  并且无论是自签CA (服务器证书,有/没有DNS项)，还是freessl 申请的证书，   
  都会弹出"不信任证书"的对话框，让你确认。   
  确认后，都能<span style="background:#cfc">**成功连接**</span>。(2023-10测)   
* 参考【[FreeRadius EAP-TLS configuration](https://wiki.alpinelinux.org/wiki/FreeRadius_EAP-TLS_configuration)】,   
  【[配置用于 PEAP 和 EAP 要求的证书模板](https://learn.microsoft.com/zh-cn/windows-server/networking/technologies/nps/nps-manage-cert-requirements)】,   
  【[将 EAP-TLS 或 PEAP 与 EAP-TLS 配合使用时的证书要求](https://learn.microsoft.com/zh-cn/troubleshoot/windows-server/networking/certificate-requirements-eap-tls-peap)】   


---------------end---------------
