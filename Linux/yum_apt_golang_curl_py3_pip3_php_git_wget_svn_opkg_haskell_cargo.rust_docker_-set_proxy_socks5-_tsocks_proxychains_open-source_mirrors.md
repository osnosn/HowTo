# [yum_apt_golang_curl_py3_pip3_php_git_wget_svn_opkg_haskell_cargo.rust_docker_设置_proxy_socks5_tsocks_proxychains_国内开源镜像mirrors](https://github.com/osnosn/HowTo/blob/master/Linux/yum_apt_golang_curl_py3_pip3_php_git_wget_svn_opkg_haskell_cargo.rust_docker_-set_proxy_socks5-_tsocks_proxychains_open-source_mirrors.md)
**转载注明来源: [本文链接](https://github.com/osnosn/HowTo/blob/master/Linux/yum_apt_golang_curl_py3_pip3_php_git_wget_svn_opkg_haskell_cargo.rust_docker_-set_proxy_socks5-_tsocks_proxychains_open-source_mirrors.md)**，写于 2020-03-11.

# 各种客户端应用的代理设置，支持的代理类型

## yum, dnf
* centos7 修改 `/etc/yum.conf`
  * 如 http 代理, 添加一行 `proxy=http://192.168.2.2:80` 
  * 如 socks5 代理, 添加一行 `proxy=socks5://192.168.2.2:1080` 
  * 支持 http, ftp, https, socks4, socks4a, socks5, socks5h 这几种代理类型。
* centos8 修改 `/etc/dnf/dnf.conf`
  * 如 http 代理, 添加一行 `proxy=http://192.168.2.2:80` 
  * 如 socks5 代理, 添加一行 `proxy=socks5://192.168.2.2:1080` 
  * 同centos7, 支持 http, ftp, https, socks4, socks4a, socks5, socks5h 这几种代理类型。
  * 另, 还支持 socks, 大概是会自动判断socks4 or 5 的版本吧。(我猜测)
    * `proxy=socks://192.168.2.2:1080`
  * 支持 https 代理，
    ```
    proxy=https://usr:pwd@192.168.2.2:8080
    proxy_auth_method=basic
    proxy_sslverify=False
    ```

## apt
* 在 `/etc/apt/apt.conf` 文件中加入一行:   
  或者创建文件 `/etc/apt/apt.conf.d/99proxy.conf`
* 支持http代理: `Acquire::http::Proxy "http://usr:pwd@192.168.2.2:80";`  
  支持https代理: `Acquire::http::Proxy "https://usr:pwd@192.168.2.2:80";`  
  帮助文档`man apt-transport-https`  
* 支持socks5h代理(remote DNS解析): `Acquire::http::Proxy "socks5h://usr:pwd@192.168.2.2:1080";` 
  * 如果s5是通过 `ssh -R` 提供的，想要允许子网使用，服务端的 `sshd_config` 要设置 `GatewayPorts yes`。  
    服务端是 op-21.02 的话，`/etc/config/dropbear` 要加上 `option GatewayPorts 'on'`，并且要用 `ssh -R '*:1080'`连。  
    如果ssh是通过tsocks-1.8连接。tsocks.conf 的缺省部分,不要设置 `server =`，要设置 `fallback = yes`。  
    建议通过ncat或netcat连接，不通过tsocks或proxychains。  

## golang
* `go get` 指令支持 环境变量 http_proxy 和 https_proxy，指定普通代理。其中`go get`又使用 git 获取源码。  
   所以, 配置 git 的代理 + `export https_proxy=socks5://127.0.0.1:1080`。  
   比如直接执行`https_proxy=socks5://127.0.0.1:1080 go mod download github.com/mattn/go-sqlite3`(无GOPROXY设置)  
* 或者只用 GOPROXY=https://goproxy.io,direct 环境变量。见 【[goproxy.io](https://goproxy.io)】首页的介绍。  
  或者 GOPROXY=https://goproxy.cn,direct 环境变量。见 【[goproxy.cn](https://goproxy.cn)】首页的介绍。  
  还有几个可用, (https://)gonexus.dev/ , https://mirrors.aliyun.com/goproxy/ , (https://)athens.azurefd.net , (https://)gocenter.io ,, https://repo.huaweicloud.com/repository/goproxy/ ,    
  这个用不了, https://proxy.golang.org ,   
  * GOPROXY= 只接受 https 。如要用 http，则要设置 GO111MODULE=on 。
  * goproxy.io 不是用常规的代理协议。go 访问 github.com , 会以 https://goproxy.io/github.com/xxx 的形式访问。
  * Go 1.13 及以上（推荐）  
    `go env -w GO111MODULE=on`  
    `go env -w GOPROXY=https://goproxy.cn,direct`  
    其实写在 "~/.config/go/env" 文件中。  
  * Go 1.12 及以下  
    `export GO111MODULE=on`  
    `export GOPROXY=https://goproxy.cn,direct`  
* "net/http" 包, 缺省支持 http 和 socks5 代理.  
  ```
  proxystr="http://192.168.2.2:80"      //http proxy
  proxystr="socks5://192.168.2.2:1080"  // socks5 proxy(remote DNS解析)
  proxyURL, err = url.Parse(proxystr)
  tr = &http.Transport{
     TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
     Proxy:           http.ProxyURL(proxyURL),
  }
  client = &http.Client{Timeout: time.Duration(20) * time.Second, Transport: tr}
  req, _ = http.NewRequest("GET", myurl, nil)
  resp, err := client1.Do(req)
     ...
     ...
  ```
* golang net.DialTCP( ) 不支持http的CONNECT代理，也不支持socks5代理。
  * 自己实现吧。这两种代理都比较简单,协议并不复杂。
  * **实现参考:** [一个简单的Golang实现的Socks5 Proxy](http://www.imooc.com/article/275797)
  * 注意:如果不打算提供账号，发送 05 01 00 就好。 如果你发 05 02 00 02, 有的socks5服务即使不需要账号认证也会回复 05 02, 导致认证失败。
* "net/http" 包中的socks5支持，来自`net/http/socks_bundle.go`中的`func socksNewDialer()`
   * 文档: ["net/http"](https://godoc.org/net/http)
* socks5的另一个支持包是，`import "golang.org/x/net/proxy"`中的`func SOCKS5()`，最终的支持来自`import "golang.org/x/net/internal/socks"`。（golang.org 难以访问，比较累。）
   * 文档: ["golang.org/x/net/proxy"](https://godoc.org/golang.org/x/net/proxy), ["golang.org/x/net/internal/socks"](https://godoc.org/golang.org/x/net/internal/socks)


## wget
* 支持环境变量 http_proxy= , https_proxy= 
* 或者设置 ~/.wgetrc
  ```
  https_proxy = http://user:pwd@127.0.0.1:8087/
  http_proxy = http://user:pwd@127.0.0.1:8087/
  ftp_proxy = http://user:pwd@127.0.0.1:8087/
  #proxy_user=user
  #proxy_password=pwd
  ### If you do not want to use proxy at all, set this to off.
  use_proxy = on
  ### 以下也支持
  #httpsproxy = http://user:pwd@127.0.0.1:8087/
  #httpproxy = http://user:pwd@127.0.0.1:8087/
  #ftpproxy = http://user:pwd@127.0.0.1:8087/
  #proxyuser=user
  #proxypassword=pwd
  #useproxy = on
  ```
* wget 无论是环境变量，还是 .wgetrc 只支持 http 代理，不支持 https socks5   
  如果非要使用 socks5 ，那就套上 tsocks 。


## curl
* 支持  `http://` `https://` `socks4://` `socks4a://` `socks5://` `socks5h://`
  * `socks5h://`(remote DNS解析)
* 支持 环境变量, 比如: 
  * `http_proxy=socks5://1.1.1.1:1080`
  * `https_proxy=socks5://1.1.1.1:1080`
  * `ALL_PROXY=socks5://1.1.1.1:1080`
* 设置 ~/.curlrc , 支持两种格式
  ```
  ### 代理设置
  --proxy http://user:pw@127.0.0.1:888
  #proxy=http://user:pw@127.0.0.1:888
  #proxy=socks5h://user:pw@127.0.0.1:1080
  #proxy=https://user:pw@127.0.0.1:888
  #proxy-insecure   #忽略代理的证书
  ### 跟随重定向，follow location
  location
  #--location
  ```

## python3  urllib.request ; requests ; pycurl
* urllib.request
  ```python
  import urllib.request,ssl
  context = ssl._create_unverified_context()
  #myhh=urllib.request.ProxyHandler({
  #  'http'  : 'http://192.168.2.2:80',
  #  'https' : 'http://192.168.2.2:80',
  #  })
  #opener = urllib.request.build_opener(myhh,urllib.request.HTTPSHandler(context=context))#不验证证书
  opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=context))#不验证证书
  opener.add_handler(urllib.request.ProxyHandler({
      'http' : 'http://192.168.2.2:80', #py3检查第一行的代理协议，支持 http:// https://
      'https' : 'http://192.168.2.2:80' #py3不检查,无论写什么，代理协议与第一行相同。
      }))
  req=urllib.request.Request('http://baidu.com')
  con=opener.open(req)
  print(con.read())
  ```
* py3 的 urllib.request 不直接支持 socks5 代理。  
  需要 PySocks 包支持。`pip3 install PySocks` 或 `apt install python3-socks` 或 `yum install python36-pysocks` 或 `dnf install python3-pysocks`
  ```python
  import urllib,urllib.parse,urllib.request
  import ssl
  import socks,sockshandler
  
  context = ssl._create_unverified_context()
  mys5=sockshandler.SocksiPyHandler(socks.SOCKS5,'192.168.2.2',1080,rdns=True) #add_handler()无效
  #mys5=sockshandler.SocksiPyHandler(socks.SOCKS5,'192.168.2.2',1080,username='user',password='pwd',rdns=True) #add_handler()无效
  opener = urllib.request.build_opener(mys5,urllib.request.HTTPSHandler(context=context))#不验证证书
  req=urllib.request.Request('http://baidu.com')
  con=opener.open(req)
  ```
* PySocks 为 py3 程序,设置全局默认代理  
  ```python
  import socks, socket
  socks.set_default_proxy(proxy_type=socks.SOCKS5, addr='192.168.1.2', port=1080, rdns=True, username='usr', password='pwd')
  #socks.set_default_proxy(proxy_type=socks.SOCKS5, addr='192.168.1.2', port=1080, rdns=True, username=None, password=None)
  socket.socket=socks.socksocket
  # proxy_type= 支持三种代理类型 socks.SOCKS4  socks.SOCKS5  socks.HTTP
  ```
* py3 的 requests-2.24 包支持http和socks5代理, (需要装PySocks)  
  ```python
  import requests
  ## verify=False 访问https时不检查证书
  # 去除不检查证书的警告
  requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
  #proxy={'http':'http://user:pwd@192.168.1.100:88','https':'http://user:pwd@192.168.1.100:88'}
  proxy={'http':'socks5://user:pwd@192.168.1.100:1080','https':'socks5://user:pwd@192.168.1.100:1080'}
  rr = requests.get(url, headers = header, allow_redirects=False,verify=False,proxies=proxy,timeout=5)
  ```
* py3 的 pycurl 也支持http和socks5代理

## pip3
* 命令行参数，`--proxy=socks5://user:pwd@192.168.1.22:1080`, `--proxy=http://user:pwd@192.168.1.22:8080`
* `~/.pip/pip.conf` 用户配置文件中: (顺便改镜像为"华为云")
  ```
  [global]
  # timeout 缺省 15
  timeout = 60
  index-url = https://repo.huaweicloud.com/repository/pypi/simple
  #index-url = https://mirrors.aliyun.com/pypi/simple/
  proxy = socks5://usr:pwd@192.168.1.22:1080
  #proxy = http://usr:pwd@192.168.1.22:8080
  ```
  `socks5://` 需要 PySocks 包支持。`pip3 install PySocks` 或 `apt install python3-socks` 或 `yum install python36-pysocks` 或 `dnf install python3-pysocks`


## PHP
* 使用 php 的 curl 函数，支持http和socks5代理。 `$ch=curl_init();`
  * `curl_setopt($ch, CURLOPT_PROXY, 'socks5h://user:pwd@192.168.1.1:1080');`
  * `curl_setopt($ch, CURLOPT_PROXY, 'http://user:pwd@192.168.1.1:8080');`

## tsocks 1.8
* debian : 用 `apt install tsocks`
* centos : 去 http://pkgs.org/ 搜索rpm包。
  * 这个可以用在centos8:[下载页面](https://centos.pkgs.org/7/nux-misc-x86_64/tsocks-1.8-0.14.beta5.el7.nux.x86_64.rpm.html) , [下载链接](https://li.nux.ro/download/nux/misc/el7/x86_64/tsocks-1.8-0.14.beta5.el7.nux.x86_64.rpm), 用 `rpm -i ...` 安装即可。

## proxychians4
* proxychains-ng, 即 proxychains4 。是一个类似 tsocks 的命令。
  * tsocks 只支持socks5，可以根据不同的destination ip，走不同的 socks5。没有socks5嵌套。
  * proxychains 支持 http, socks5，没有destination ip的设置，proxy可以嵌套。

## graftcp
* 【https://github.com/hmgle/graftcp】
* 【[proxychains和graftcp的比较](https://blog.ykai.cc/proxychainshe-graftcpde-bi-jiao/)】
* proxychains使用了LD_PRELOAD环境变量。替换系统的动态库glibc，达到使用socks5目的。对使用动态库的程序有效。  
  graftcp的思路则是通过ptrace调用来截获子进程的connect连接。对静态编译的程序也有效，比如golang程序。  
  graftcp是用c 和 golang写的。github项目的releases中也没有编译好的程序下载。debian中没有预编译包安装。只能自己编译。  

## toh
* 【https://github.com/rkonfj/toh】  
  TCP/UDP over HTTP/WebSocket

## git
* 【[GIt设置代理](https://www.jianshu.com/p/b481d2a42274)】,【[git如何设置使用代理](https://www.jianshu.com/p/290152303598)】
  【[Configure Git to use a proxy](https://gist.github.com/evantoli/f8c23a37eb3558ab8765)】
* 不能用 tsocks 来套，会出错。
* 设置  
  git config --global https.proxy http://user:psw@127.0.0.1:1080  
  git config --global https.proxy https://user:psw@127.0.0.1:1080  
  git config --global http.proxy 'socks5://user:psw@127.0.0.1:1080'  
  git config --global https.proxy 'socks5://user:psw@127.0.0.1:1080'  
  密码中有特殊字符的要用 % 编码，比如 @ --> %40  
* 取消  
  git config --global --unset http.proxy  
  git config --global --unset https.proxy  
* git "--global" 的配置在 `~/.gitconfig`, "--local" 的配置在当前项目的 `.git/config`  
* 有一个公共代理站，见【[ghproxy.com](https://ghproxy.com/)】
* 【[为 git 和 ssh 设置 socks5 协议的代理](https://blog.systemctl.top/2017/2017-09-28_set-proxy-for-git-and-ssh-with-socks5/)】
  【[如何为 Git 设置代理](https://segmentfault.com/q/1010000000118837)】
  * `ssh://`, 使用 ProxyCommand  
    在 `.ssh/config` 中配置连接 github的 ssh账号，  
    使用`ProxyCommand /bin/nc -x 192.168.x.xx:1080 %h %p`。  
    或，使用`ProxyCommand /usr/bin/ncat --proxy-type socks5 -x 192.168.x.xx:1080 --proxy-auth usr:pwd %h %p`。  
  * `git://`, 在 `man git-config` 有提到。  
    使用 `git config --global core.gitProxy '/opt/mypxy.sh'`  
    或者 `export GIT_PROXY_COMMAND=/opt/mypxy.sh`  
    ```
    # mypxy.sh
    ncat --proxy ... "$@"
    ```

## svn
* svn 配置代理，支持 http 代理，不支持 socks5  
  修改 `~/.subversion/servers` 中 `[global]` 的  
  `http-proxy-host`  
  `http-proxy-port`  
  `http-proxy-username`  
  `http-proxy-password`  

## haskell stack
* 使用环境变量  
  ```
  export http_proxy=http://user:pwd@192.168.1.1:80
  export https_proxy=http://user:pwd@192.168.1.1:80
  stack setup
  ```

## rust
* "~/.cargo/config" 更换源，代理，(2022-06)
  ```
  [source.crates-io]
  #registry = "https://github.com/rust-lang/crates.io-index"
  registry = "sparse+https://index.crates.io/"        
  replace-with = 'ustc'
  [source.ustc]
  #registry = "git://mirrors.ustc.edu.cn/crates.io-index"
  registry = "sparse+https://mirrors.ustc.edu.cn/crates.io-index/"
  [http]
  proxy = "http://user:pass@192.168.0.1:3333"
  check-revoke = false
  [https]
  proxy = "http://192.168.0.1:3333"
  #proxy = "socks5://user:pass@192.168.0.1:23456"
  ```
  缺点，cargo search 无法使用镜像。
* 指定搜索还是用 crates-io，加入 `~/.cargo/config`
  ```
  [registry]
  default = "crates-io"
  ```
* 【[Rust Crates 源使用帮助](http://mirrors.ustc.edu.cn/help/crates.io-index.html)】
* **cargo** 支持环境变量,   
  **rustup** 也使用环境变量,   
  ```
  http_proxy="http://user:pass@127.0.0.1:1080"
  https_proxy="http://user:pass@127.0.0.1:1080"
  ```
* 使用字节跳动的镜像。【[rsproxy.cn](https://rsproxy.cn/#getStarted)】(2023-10)
  ```
  [source.crates-io]
  replace-with = 'rsproxy-sparse'
  [source.rsproxy]
  registry = "https://rsproxy.cn/crates.io-index"
  [source.rsproxy-sparse]
  registry = "sparse+https://rsproxy.cn/index/"
  [registries.rsproxy]
  index = "https://rsproxy.cn/crates.io-index"
  [net]
  git-fetch-with-cli = true
  [registry]
  default = "rsproxy"
  ```


## openWRT opkg
* `/etc/opkg.conf` 例子
  ```
  optinon no_check_certificate 1
  optinon http_proxy 127.0.0.1:7890
  # optinon http_proxy http://user:pass@127.0.0.1:7890/
  #不支持# optinon https_proxy 127.0.0.1:7890
  #不支持# optinon https_proxy http://user:pass@127.0.0.1:7890/
  optinon ftp_proxy 127.0.0.1:7890
  option http_timeout 5
  optinon proxy_user abc
  optinon proxy_passwd def
  ```
* op-19,op-21,op-22, 默认安装的wget(其实是uclient-fetch)，**仅支持通过无认证的代理访问http**，不支持通过代理访问https，不支持代理的认证。(可以建本地的无认证代理,再转发)  
  除非**安装完整版wget**，op-19用`opkg install wget`，op-21,op-22用`opkg install wget-ssl`。  
  * op21,op22中`/etc/opkg.conf`并不支持`https_proxy`的配置项。https访问只能在 `~/.wgetrc`配置，支持代理的认证。  
    http访问,配置 `/etc/opkg.conf` 或者 `~/.wgetrc` (二选一)，支持代理认证。  
  * 应该也支持,环境变量 `http_proxy=` 和 `https_proxy=`，(未测试)。  
  * 2025年安装op24，镜像站都是https，很少有http的。  
    只能根据 `opkg print-architecture`或`cat /etc/openwrt_release`确定ARCH, 去下载 ipk包。  
    先**手动下载 wget-ssl的 ipk文件**(在/packages)，以及它的两个依赖包 ipk(在/base)，上传并安装 wget-ssl。  
    然后通过设置`/root/.wgetrc`使用http代理，支持代理的认证。`https_proxy=http://usr:pwd@192.168.22.2:8080`  
    如果还是报错`wget returned 5`, 可能是op对网站的证书验证失败，<span style="background:#fcf">检查本地时间是否正确</span>，或.wgetrc中加入`check-certificate=off`  
    另: /etc/opkg.conf 中 `optinon no_check_certificate 1` 设置无效。  
* op-25, 默认安装，仅支持环境变量`https_proxy=http://xxx:8080/ apk update`, 不支持代理的认证，访问代理用"GET https://"而不是"CONNECT https"，会有兼容性问题，部分代理不支持这种方式，导致访问失败。(202606测试)  
  * **手动下载 wget-ssl的 apk文件**(在/packages)，以及它的一个依赖包 apk(在/base)，上传并安装 wget-ssl。  
    `apk add --allow-untrust libpcre2-10.47-r1.apk wget-ssl-1.25.0-r2.apk`, 防止报错`UNTRUSTED signature`。  
    然后通过设置`/root/.wgetrc`使用http代理，支持代理的认证。  
* 换源,清华大学:`sed -i s_downloads.openwrt.org_mirrors.tuna.tsinghua.edu.cn/openwrt_ /etc/opkg/distfeeds.conf`  
  换浙大源，`sed -i s_vsean.net/openwrt_zju.edu.cn/immortalwrt_  /etc/opkg/distfeeds.conf`  
  换科大源，`sed -i s_vsean.net/openwrt_ustc.edu.cn/immortalwrt_  /etc/opkg/distfeeds.conf`  
  换上交大源，`sed -i s_vsean.net/openwrt_sjtug.sjtu.edu.cn/immortalwrt_  /etc/opkg/distfeeds.conf`  
  换北大源，`sed -i s_vsean.net/openwrt_pku.edu.cn/immortalwrt_  /etc/opkg/distfeeds.conf`  

## docker pull 设置通过 http 代理
* 【[docker pull通过http代理服务拉取镜像&docker配置通过私库拉取镜像](https://blog.csdn.net/jxlhljh/article/details/120176970)】，  
  【[如何配置docker通过代理服务器拉取镜像](https://www.cnblogs.com/abc1069/p/17496240.html)】，  
  【[Docker 在内网服务器通过配置代理访问外网拉取镜像](https://blog.csdn.net/chrisy521/article/details/128644578)】  
* (方式1)设置 `/etc/systemd/system/docker.service.d/http-proxy.conf` (docker.service.d/ 目录需要手工创建)。  
  支持 http,socks5, 内容为，  
  ```
  [Service]
  Environment="HTTP_PROXY=http://proxy.example.com:80"
  Environment="HTTPS_PROXY=https://proxy.example.com:443"
  #Environment="HTTPS_PROXY=socks5://user:pwd@proxy.example.com:1080"
  ```
  `systemctl daemon-reload; systemctl restart docker` 重启docker服务。  
  `systemctl show --property=Environment docker` 检查确认环境变量已经生效。  
* (方式2)设置 `/etc/docker/daemon.json`
  ```
  {
    "proxies": {
      "http-proxy": "http://usr:pwd@192.168.1.2:8888",
      "https-proxy": "http://usr:pwd@192.168.1.2:8888"
    }
  }
  ```
  重启服务`systemctl restart docker` 生效  
  检查: `docker info | grep -i proxy` 有输出。  
* 【[修改Docke上传/下载并发线程数（解决docker: unexpected EOF.）](https://developer.aliyun.com/article/1124330)】,  
  【[docker容器/etc/docker/daemon.json配置文件详解](https://www.cnblogs.com/chuyiwang/p/17577020.html)】,  
  创建/修改 文件 `/etc/docker/daemon.json` 上传/下载都设置为1，内容为:  
  ```
  {
    "max-concurrent-uploads": 1,
    "max-concurrent-downloads": 1
  }
  ```
  `systemctl daemon-reload; systemctl restart docker` 重启docker服务，生效。  
* 配置 docker 容器，走 proxy。  
  配置 `~/.docker/config.json`，具体方法上网搜索。  
  【[Use the Docker command line](https://docs.docker.com/engine/reference/commandline/cli/#change-the-docker-directory)】,【[Configure Docker to use a proxy server](https://docs.docker.com/network/proxy/)】,  
*   `docker image ls -a` 列出所有的image，按需删除。  
  【[清理Docker占用的磁盘空间](https://zhuanlan.zhihu.com/p/386025157)】,   
  `docker image prune`,`docker builder prune`,`docker system prune` (会删除没有被 container 引用的image)。  

## acme.sh
* 因为acme.sh使用"curl"，可以创建 "~/.curlrc" 配置代理。
* 或指定 "--use-wget" 参数，用 "~/.wgetrc" 配置代理。
* 也支持 `proxychains4 -q acme.sh --renew -d xxx.xxx.com`
* acme.sh 默认使用 curl，curl支持环境变量 "HTTP_PROXY=", "HTTPS_PROXY="，大小写都支持。  
  比如`https_proxy=socks5h://usr:pwd@127.0.0.1:1080  ./acme.sh --upgrade`  
  这些ENV变量，写在 account.conf 或 acme.sh.env 中并不生效。  



## ios 设置自动代理
* 【[ios 设置自动代理](http://foolishflyfox.xyz/blog/2020/04/11/vpn/ios-auto-agent/)】
* 就是使用 .pac 文件，URL 就是指向这个.pac文件的连接。  
  ```
  function FindProxyForURL(url, host){
    return "SOCKS 192.168.1.120:1090";
  }
  ```



# 国内开源镜像站, mirrors
* 【[国内镜像站列表](https://gitee.com/taadis/mirrors-in-china/)】
* 【[国内开源镜像站点汇总](https://www.cnblogs.com/geek233/p/16160091.html)】




-----
**转载注明来源: 本文链接 https://github.com/osnosn/HowTo/blob/master/Linux/yum_apt_golang_curl_py3_pip3_php_git_wget_svn_opkg_haskell_cargo.rust_docker_-set_proxy_socks5-_tsocks_proxychains_open-source_mirrors.md**.

