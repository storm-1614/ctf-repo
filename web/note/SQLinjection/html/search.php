<?php
// LIKE 查询注入 (WHERE title LIKE '%xxx%')
// 访问: search.php?q=新闻

$conn = mysqli_connect("db", "root", "root", "test");
mysqli_set_charset($conn, 'utf8mb4');
$keyword = $_GET['q'] ?? '';

$sql = "SELECT title, content FROM wp_news WHERE title LIKE '%$keyword%'";

echo "<!DOCTYPE html><html lang='zh'><head><meta charset='UTF-8'><title>搜索型注入</title>
<style>body{font-family:'Segoe UI',sans-serif;max-width:800px;margin:50px auto;background:#1a1a2e;color:#e0e0e0;}
h1{color:#e94560;}pre,code{background:#0f3460;padding:2px 6px;border-radius:3px;}
.result{background:#16213e;padding:15px;margin:10px 0;border-radius:5px;}
a{color:#e94560;}</style></head><body>";

echo "<h1>搜索型 SQL 注入</h1>";
echo "<p>执行的SQL: <code>" . htmlspecialchars($sql) . "</code></p>";
echo "<a href='index.php'>← 返回首页</a><hr>";

echo "<form method='GET'><input type='text' name='q' value='" . htmlspecialchars($keyword) . "' placeholder='输入搜索关键词' style='padding:10px;width:60%;border-radius:4px;border:1px solid #0f3460;background:#16213e;color:#fff;'><input type='submit' value='搜索' style='padding:10px 20px;background:#e94560;color:#fff;border:none;border-radius:4px;cursor:pointer;'></form><br>";

$res = mysqli_query($conn, $sql);
if ($res && mysqli_num_rows($res) > 0) {
    while ($row = mysqli_fetch_assoc($res)) {
        echo "<div class='result'><h3>" . htmlspecialchars($row['title']) . "</h3>";
        echo "<p>" . htmlspecialchars($row['content']) . "</p></div>";
    }
} else {
    echo "<p>未找到结果: " . htmlspecialchars(mysqli_error($conn)) . "</p>";
}

echo "<details><summary>提示</summary><p>闭合 <code>%'</code> 和 <code>'%</code>，前面用 <code>')</code> 闭合前面的 <code>%'</code>，后面用 <code>#</code> 注释掉 <code>'%</code></p></details>";

mysqli_close($conn);
echo "</body></html>";
?>
