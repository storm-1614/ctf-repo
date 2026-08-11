<?php
// 字符型 SQL 注入 (WHERE id = '$id')
// 访问: sql2.php?id=1' OR '1'='1

$conn = mysqli_connect("db", "root", "root", "test");
if (!$conn) {
    die("数据库连接失败: " . mysqli_connect_error());
}
mysqli_set_charset($conn, 'utf8mb4');

$id = $_GET['id'];
$sql = "SELECT title, content FROM wp_news WHERE id='$id'";

$res = mysqli_query($conn, $sql);
echo "<!DOCTYPE html><html lang='zh'><head><meta charset='UTF-8'><title>字符型注入</title>
<style>body{font-family:'Segoe UI',sans-serif;max-width:800px;margin:50px auto;background:#1a1a2e;color:#e0e0e0;}
h1{color:#e94560;}pre{background:#0f3460;padding:15px;border-radius:5px;overflow-x:auto;}
a{color:#e94560;}.error{color:#ff6b6b;}</style></head><body>";

echo "<h1>字符型 SQL 注入</h1>";
echo "<p>执行的SQL: <code>" . htmlspecialchars($sql) . "</code></p>";
echo "<a href='index.php'>← 返回首页</a><hr>";

if ($res && mysqli_num_rows($res) > 0) {
    while ($row = mysqli_fetch_assoc($res)) {
        echo "<h2>" . htmlspecialchars($row['title']) . "</h2>";
        echo "<p>" . htmlspecialchars($row['content']) . "</p>";
    }
} else {
    echo "<p class='error'>查询结果为空或SQL错误: " . htmlspecialchars(mysqli_error($conn)) . "</p>";
}

mysqli_close($conn);
echo "</body></html>";
?>
