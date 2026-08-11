<?php
// 数字型 SQL 注入 (WHERE id=$id)
// 容器内连接 hostname=db
// 访问: sql1.php?id=1
// Payload: sql1.php?id=-1 UNION SELECT username,password FROM users

$conn = mysqli_connect("db", "root", "root", "test");
if (!$conn) {
    die("数据库连接失败: " . mysqli_connect_error());
}
mysqli_set_charset($conn, 'utf8mb4');

$id = $_GET['id'] ?? 1;
$sql = "SELECT title, content FROM wp_news WHERE id=$id";

echo "<!DOCTYPE html><html lang='zh'><head><meta charset='UTF-8'><title>数字型注入</title>
<style>body{font-family:'Segoe UI',sans-serif;max-width:800px;margin:50px auto;background:#1a1a2e;color:#e0e0e0;}
h1{color:#e94560;}pre{background:#0f3460;padding:15px;border-radius:5px;overflow-x:auto;}
a{color:#e94560;}.error{color:#ff6b6b;}.result{background:#16213e;padding:15px;margin:10px 0;border-radius:5px;}</style></head><body>";

echo "<h1>数字型 SQL 注入</h1>";
echo "<p>执行的SQL: <code>" . htmlspecialchars($sql) . "</code></p>";
echo "<a href='index.php'>← 返回首页</a><hr>";

$res = mysqli_query($conn, $sql);
if ($res && mysqli_num_rows($res) > 0) {
    while ($row = mysqli_fetch_assoc($res)) {
        echo "<div class='result'>";
        echo "<h2>" . htmlspecialchars($row['title']) . "</h2>";
        echo "<p>" . htmlspecialchars($row['content']) . "</p>";
        echo "</div>";
    }
} else {
    echo "<p class='error'>查询结果为空或SQL错误: " . htmlspecialchars(mysqli_error($conn)) . "</p>";
}

mysqli_close($conn);
echo "</body></html>";
?>
