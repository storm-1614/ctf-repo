## 题面
5a6d78685a3374585a57786a6232316c5833527658324e6f5957356e5932686c626d64695a544639  

## 思路
就是要解密上面那个。  
第一眼以为是 base64，丢进去解密发现是乱码。分析发现特别像 16 进制数。使用 xxd -r -p 解密出：
```
ZmxhZ3tXZWxjb21lX3RvX2NoYW5nY2hlbmdiZTF9
```

是 base64，再管道给 base64 最后出来 flag:
```
flag{Welcome_to_changchengbe1}
```

最终 exp:
``` bash
echo "5a6d78685a3374585a57786a6232316c5833527658324e6f5957356e5932686c626d64695a544639" | xxd -r -p | base64 --decode
```
