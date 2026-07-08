## 账密结构体：
查询时：
账号 31 字节 char *
密码 31 字节 char *


## sub_163b
sub_15d2 通过 seccomp_rule_add 禁用 execve 相关系统调用  
bss 段 qword_70C0 存地址，由 malloc 分配 0x400 的内存  
v0 是 qword_70C0 偏移 50 的地址，为 0x696D6461  
qword_70C0 + 104 是来自 /dev/urandom 的随机数

## sub_17C0
登录界面输出  
v3 选择  

## login
s2 用户名  
v4 密码  
长度都为 34
### sub_1b9d 
进入 admin  
用户名：qword_70C0 + 50(0x696D6461)  
密码：qword_70C0 + 104(随机数)  

### sub_3220
admin 操作界面  

## sub_19E7
注册函数  
不能注册 admin  

### sub_181B
堆分配内存用于存储用户名和密码  
qword_7060 同样是内存地址，一个结构体数组？ 

---
v1 索引



