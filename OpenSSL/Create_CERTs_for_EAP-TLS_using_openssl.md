## [Create CERTs for EAP-TLS using OpenSSL](https://github.com/osnosn/HowTo/blob/master/OpenSSL/Create_CERTs_for_EAP-TLS_using_openssl.md)
## [用openssl为EAP-TLS生成证书（CA证书,服务器证书,用户证书）](https://www.cnblogs.com/osnosn/p/10597897.html)
**来源: https://www.cnblogs.com/osnosn/p/10597897.html**
写于: 2019-03-27.   

> 本文参考了大神的文章:   
> 　[搭建一个「最安全」的Wi-Fi网络](https://zhuanlan.zhihu.com/p/28927420)，[楠站](https://zenandidi.com/archives/948)，

本文是为**"[CentOS7用hostapd做radius服务器为WiFi提供802.1X企业认证](https://www.cnblogs.com/osnosn/p/10593297.html)"** 中,WiFi的EAP-TLS认证,准备证书。   
如果想为WEB服务器生成自签名证书,我补充了一篇笔记: **"[用openssl为WEB服务器生成证书](https://www.cnblogs.com/osnosn/p/10608455.html)"**。   

我用的是openssl-1.0.2k.    
脚本支持生成RSA，ECC证书。   运行时带参数指定类型。   
-->开始。按以下路径建立文件，脚本。   
```
ssl_create-cert/   <-- 这个目录, 自己随便取名
   |_  0serial
   |_  2indexdb.txt
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
`echo "2233AA1234" > 0serial` 证书序列号，自己随便编，十六进制数。

`cat /dev/null > 2indexdb.txt`  
> 此文件必须是0字节，否则openssl会报错  
> `wrong number of fields on line 1 (looking for field 6, got 1, '' left)`  

`mkdir  3certs_new  4export  user_certs`

clear_all_cert.sh
```
#!/bin/sh
# clear_all_cert.sh
if [  "$#" -ne 1  -o  "$1" != "clearall" ]; then
        echo "Usage: $0 clearall"
        echo -e "\tClear all the \"keys\" and \"certs\"."
        echo -e "\tIt will remove *.pem"
        echo -e "\tIt will remove 3certs_new/* 4export/* user_certs/*"
        echo -e "\tIt will remove ALL!!!!!"
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
if [ -f 0serial ]; then
        rm -f 0serial.old
fi
if [ -f 2indexdb.txt ]; then
        cat /dev/null > 2indexdb.txt
        rm -f 2indexdb.txt.attr 2indexdb.txt.attr.old 2indexdb.txt.old
fi
echo -e "ALL cert files removed."
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
        echo -e "\t $0  ./"
        echo -e "\t $0  a/"
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
      echo -e "\nUsage: $0  {rsa2048|rsa4096|ec256|ec384}\n"
      exit
      ;;
esac

exportdir="4export"

echo "Self-sign the root CA..."
echo "No Root CA key found. Generating one"
openssl req -x509 -nodes -days 36500 -newkey ${keytype} -keyout ca_key.pem -out ca_cert.pem -new -sha512 -config openssl.cnf -extensions v3_ca -rand /dev/urandom -utf8 -subj "/C=CN/ST=广东/L=gz/O=Home/CN=Wifi EAP Root CA/"  && \
openssl x509 -outform der -in ca_cert.pem -out ./${exportdir}/CA.crt  && \
openssl x509 -in ca_cert.pem -noout -text > ca_cert.txt
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
      echo -e "\nUsage: $0  {rsa2048|rsa4096|ec256|ec384}\n"
      echo "server证书建议用RSA。"
      echo "ECC server证书会导致安卓无法连接。错误为\"no shared cipher\"."
      exit
      ;;
esac

echo "Create server ssl for hostapd."
echo "No Server key found. Generating one."

openssl req -nodes -new -newkey ${keytype} -keyout server_key.pem -out server_csr.pem -config openssl.cnf -rand /dev/urandom -utf8 -subj "/C=CN/ST=广东/L=gz/O=Home/CN=WiFi Radius Server/"  && \
openssl ca -days 36500 -in server_csr.pem -out server_cert.pem -config openssl.cnf -extensions server_cert -batch  && \
rm -rf server_csr.pem
echo "You may now run ./create_crl.sh"
echo ""
```

new-user.sh
```
#!/bin/sh
# new-user.sh
# Create the user key and cert. This should be done once per cert.
if [ $# -ne 3 ]; then
   echo -e "\nUsage: $0  {rsa1024|rsa2048|rsa4096|ec256|ec384}  userName  days\n    days between 2 and 365\n"
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
      echo -e "\nUsage: $0  {rsa2048|rsa4096|ec256|ec384}  userName\n"
      exit
      ;;
esac

DAYS=${3:-1}  # default 1
if [ "${DAYS}" -gt 365 -o "${DAYS}" -lt 2 ]; then
   if [ "${DAYS}" -ne 36500 ];then
      echo -e "\nUsage: $0  {rsa1024|rsa2048|rsa4096|ec256|ec384}  userName  days\n    days between 2 and 365\n"
      exit 1
   fi
fi

exportdir="4export"

openssl req -nodes -new -newkey ${keytype} -keyout user_certs/user_${CERT}_key.pem -out user_certs/user_${CERT}_csr.pem -utf8 -subj "/C=CN/ST=广东/L=gz/O=Home/CN=WiFi ${CERT}/" && \
openssl ca -days ${DAYS} -in user_certs/user_${CERT}_csr.pem -out user_certs/user_${CERT}_cert.pem -config openssl.cnf -extensions user_cert -batch && \
rm -rf user_certs/user_${CERT}_csr.pem && \
echo -e "Export certs...\n \"Export Password\" MUST set for IOS.\n \"Export Password\" MAY empty for Android,windows."  && \
openssl pkcs12 -export -out ./${exportdir}/${CERT}.p12 -inkey user_certs/user_${CERT}_key.pem -in user_certs/user_${CERT}_cert.pem -certfile ca_cert.pem -caname "Wifi EAP RootCA" -name "${CERT}-wifi-user" -passout pass:123
# 友好名称 "-name" "-caname" windows中不支持utf8中文

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

`chmod  +x  clear_all_cert.sh  new-ca.sh  new-server.sh  create_crl.sh  copy-pem-to.sh  new-user.sh  revoke-user.sh`

openssl.cnf
```
#openssl.cnf
[ ca ]
default_ca = hostapd

[ hostapd ]
dir = .
serial = $dir/0serial
database = $dir/2indexdb.txt
new_certs_dir = $dir/3certs_new
certificate = $dir/ca_cert.pem
private_key = $dir/ca_key.pem
RANDFILE = /dev/urandom

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
certificatePolicies=ia5org,@pl_section
[ user_cert ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = CA:false
#subjectAltName = email:copy
extendedKeyUsage = clientAuth,emailProtection,timeStamping
certificatePolicies=ia5org,@pl_section

[ pl_section ]
policyIdentifier = "X509v3 Any Policy"
# 颁发者说明的链接. windows中,要导入信任之后才生效.
CPS.1 = https://your.web.com/cps/readme.html
userNotice.1=@pl_notice
[ pl_notice ]
# 颁发者说明,Issuer statment. 不支持utf8中文,因为ia5org。
explicitText="Read deail at https://your.web.com/xxx.html"
```
> userNotice.1 的文字说明，只能是英文，中文会乱码。   
> 文字说明，无论此证书是否被系统信任，查看证书时都会出现在"颁发者说明"中(Issuer Statement)。   
> CPS.1 的链接。系统未信任此证书时，是不显示的。信任后，才会出现在"颁发者说明"中(Issuer Statement)。  
> CPS.1= 可以是 "http://" 也可以是 "https://"。   
> <img src="https://github.com/osnosn/HowTo/raw/master/OpenSSL/images/EAP-TLS1.png" width="200" /><img src="https://github.com/osnosn/HowTo/raw/master/OpenSSL/images/EAP-TLS2.png" width="200" /><img src="https://github.com/osnosn/HowTo/raw/master/OpenSSL/images/EAP-TLS3.png" width="200" />

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
server cert: ECC 会导致Android8 连接失败, 错误为"no shared cipher"。建议用RSA。   
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

`chmod  +x  clear_all_cert.sh  new-ca.sh  new-server.sh  create_crl.sh  copy-pem-to.sh  new-user.sh  revoke-user.sh`

给android导入用户证书一定要用p12格式，不能用pem格式。   
Android不认pem格式中的密钥，只认公钥。导致没密钥不能用于连接WIFI。   

使用方法:
>  修改 C=/ST=/L=/O=/CN= 的内容合适你自己。这些项可以使用中文。  
>  修改 openssl.cnf 中 CPS.1= 和 explicitText= 。  
>  在IOS，windows中可以看到，可以写漂亮点。主要是CN=写漂亮点。会显示为证书名。  
> Android没地方看证书描述。写啥，Android都看不到。  
>  ./clear_all_cert.sh clearall  
> ./new-ca.sh  ec256  
> ./new-server.sh  rsa2048    #服务器证书建议用RSA  
> ./create_crl.sh   
> ./copy-pem-to.sh  hostapd_conf_dir/  
> service restart hostapd  
> ./new-user.sh  ec256  user1  36500   
> ./new-user.sh  ec256  user2  36500   
> copy xx.p12 file from "4export/" 目录，分发给用户。   

---------------end---------------
