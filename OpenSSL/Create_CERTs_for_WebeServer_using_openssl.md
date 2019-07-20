## [Create Certification for WebServer using OpenSSL](https://github.com/osnosn/HowTo/blob/master/OpenSSL/Create_CERTs_for_WebeServer_using_openssl.md)
## [用openssl为WEB服务器生成证书（自签名CA证书,服务器证书）](https://www.cnblogs.com/osnosn/p/10608455.html) 
Written in 2019-03-28.

* 不想用自签名证书，想在网上申请一个免费服务器证书，见这篇: **[去freessl.org申请免费ssl服务器证书](https://www.cnblogs.com/osnosn/p/10627969.html)**   

以下内容是用自签名证书，为网站生成服务器证书。   
照着这一篇**"[用openssl为EAP-TLS生成证书（CA证书,服务器证书,用户证书）](https://www.cnblogs.com/osnosn/p/10597897.html)"**，建立所有文件。   
脚本可以生成RSA, ECC证书。运行时带参数指定类型。    

其中openssl.cnf 按以下新增几行。用于匹配你的服务器域名，或者是IP。   
openssl.cnf
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
certificatePolicies=ia5org,@pl_section
subjectAltName = @dns_names    <---新增
[ dns_names ]             <---新增
DNS.1 = my.domain.com    <---新增
DNS.2 = your.domain.net    <---新增
IP.1 = 1.2.3.4              <---新增
IP.2 = 5.6.7.8              <---新增
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

只有一个域名，就只写 `DNS.1=`，其他的不要了。   
有多个域名，配置中就写 `DNS.1=` , `DNS.2=` , `DNS.3=` ... `DNS.9=`   
可以写通配符域名，`DNS.1=*.mydom.org`，   
将匹配所有以 `.mydom.org` 的所有域名。如: `abc.mydom.org` , `www.mydom.org` ...   
但**不匹配** `mydom.org`    
所以通配符域名一般写两行 `DNS.1=mydom.org` , `DNS.2=*.mydom.org`   

使用方法，只使用这几个命令:   
>    `./clear_all_cert.sh` 清除所有证书。   
>  modify C/ST/L/O/CN in new-ca.sh,new-server.sh,newuser.sh, 可以使用中文。   
>  modify openssl.cnf:   
>  　CPS.1=   
>  　explicitText=   
>  　[ dns_names ]   
>  　 DNS.1=   
>  　 DNS.2=   
> `new-ca.sh` 创建自签名root证书。   
> `new-server.sh` 创建web用的服务器证书。   

这三个文件，就是用于配置web服务器需要的证书。   
`ca_cert.pem` , ` server_cert.pem` , `server_key.pem`

如需要，参考以下证书格式转换的指令:   
> 查看/打印 pem 证书   
> `openssl x509 -in ca_cert.pem -text -noout`  
> `openssl x509 -in server_cert.pem -text -noout`  
> 把 pem 转为 der 格式，(证书,密钥)     
> `openssl x509 -outform der -in server_cert.pem -out server.cer` 服务器证书。  
> `openssl rsa -in server_key.pem -outform der -out server_key.cer` 服务器密钥。  
> 把 pem 转为 P12 格式(pfx)，(证书,密钥)，友好名称不支持utf8中文。  
> `openssl pkcs12 -export -out server.p12 -inkey server_key.pem -in server_cert.pem -certfile ca_cert.pem -caname"ca friendly name" -name "friendly name"`   
> 把 p12 转 jks，   
> `用java的 keytool 工具转换/导入`   
> 把 pem 转 pkcs#7 格式，(证书)   
> `openssl crl2pkcs7 -nocrl -certfile server_cert.pem -out server.p7b`   

不想用自签名证书，那去网上申请一个免费服务器证书吧: **[去freessl.org申请免费ssl服务器证书](https://www.cnblogs.com/osnosn/p/10627969.html)**   

--------- end ---------
