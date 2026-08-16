## 信息收集
### 扫描器
本质：批量 connect。比如 `nmap -sT` 就是逐个端口试 TCP 握手，如果能连就说明端口开着。  

信息收集四件套：端口 → 服务 → 版本 → 漏洞（CVE/exp）  

#### 扫描类型
- 主机发现：`-sn`（ping 扫描）
- TCP 全连接：`-sT`（三次握手完成，慢但准）
- SYN 半开：`-sS`（只发 SYN，不回握手，快、隐蔽，需要 root）
- UDP：`-sU`（慢，容易误报，但能扫出 DNS/SNMP 这种）
- 版本探测：`-sV`（连上去抓 banner，识别服务+版本）
- OS 指纹：`-O`（根据 TCP 栈特征猜系统）


对虚拟机上的 Metasploitable2 做扫描：  
##### 找靶机 ip:
``` bash
nmap -sn 192.168.122.0/24
```
输出：
```
❯ nmap -sn 192.168.122.0/24
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-16 20:33 +0800
Nmap scan report for 192.168.122.1
Host is up (0.00010s latency).
Nmap scan report for 192.168.122.228
Host is up (0.00027s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 3.51 seconds
```
确定是 192.168.122.228。  

##### TCP 端口扫描
`-sS` 做全端口 SYN 扫描。发送 SYN 包，收到 SYN/ACK 则视为端口开放，但不发送最后的ACK包，不建立完整连接。速度更快，半开放扫描隐蔽性更高。  

``` bash
sudo nmap -sS -p- 192.168.122.228
```

输出：  
```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-16 20:35 +0800
Nmap scan report for 192.168.122.228
Host is up (0.15s latency).
Not shown: 65505 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
22/tcp    open  ssh
23/tcp    open  telnet
80/tcp    open  http
...
3306/tcp  open  mysql
34038/tcp open  unknown
45091/tcp open  unknown
50015/tcp open  unknown
60502/tcp open  unknown
MAC Address: 52:54:00:32:1D:0C (QEMU virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 7.08 seconds
```

`-sT` 做 TCP 的全连接扫描。完成 TCP 三次握手建立完整连接后关闭。速度慢，隐蔽性较低。

##### 对已知端口比如 21, 22, 23, 80, 3306 做版本识别。  

```bash
 sudo nmap -sV -p 21,22,23,80,3306 192.168.122.228
```

输出：  
```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-16 20:38 +0800
Nmap scan report for 192.168.122.228
Host is up (0.00053s latency).

PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 2.3.4
22/tcp   open  ssh     OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp   open  telnet  Linux telnetd
80/tcp   open  http    Apache httpd 2.2.8 ((Ubuntu) DAV/2)
3306/tcp open  mysql   MySQL 5.0.51a-3ubuntu5
MAC Address: 52:54:00:32:1D:0C (QEMU virtual NIC)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.78 seconds
```

可以看到选定端口的版本号。  

##### 获取操作系统指纹
还可以根据 TCP 栈的特征得到操作系统信息：  

```bash
sudo nmap -O 192.168.122.228
```

输出：  

```
8180/tcp open  unknown
MAC Address: 52:54:00:32:1D:0C (QEMU virtual NIC)
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop

OS detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.96 seconds
```

##### NSE 脚本引擎
``` bash
nmap --script=default 192.168.122.228  # 默认脚本集
nmap --script=vuln 192.168.122.228 # 漏洞探测
nmap --script=ftp-vsftpd-backdoor -p21 192.168.122.228 # 精准验证 CVE-2011-2523
```

**扫描器的的终点是发现漏洞，不是发现端口。**  
