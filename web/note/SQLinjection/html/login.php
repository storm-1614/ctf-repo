<?php
// 登录绕过练习 (POST)
// 万能密码: username=admin&password=' OR '1'='1

$conn = mysqli_connect("db", "root", "root", "test");
mysqli_set_charset($conn, 'utf8mb4');

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
?>

<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>登录绕过</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; max-width: 500px; margin: 50px auto; background: #1a1a2e; color: #e0e0e0; }
        h1 { color: #e94560; }
        input { width: 100%; padding: 10px; margin: 8px 0; border: 1px solid #0f3460; border-radius: 4px; background: #16213e; color: #fff; }
        input[type="submit"] { background: #e94560; color: white; cursor: pointer; font-weight: bold; }
        pre { background: #0f3460; padding: 10px; border-radius: 5px; overflow-x: auto; }
        a { color: #e94560; }
        .card { background: #16213e; border-radius: 8px; padding: 20px; margin: 15px 0; }
        .success { color: #2ecc71; }
        .error { color: #e74c3c; }
        .hint { font-size: 0.85em; color: #888; }
    </style>
</head>
<body>
    <h1>登录绕过练习</h1>
    <a href="index.php">← 返回首页</a>

    <?php if ($logged_in): ?>
        <div class="card" style="border: 2px solid #2ecc71;">
            <h2 class="success"><?php echo $message; ?></h2>
            <p>你成功绕过了登录验证！</p>
        </div>
    <?php elseif ($message): ?>
        <div class="card" style="border: 2px solid #e74c3c;">
            <p class="error"><?php echo htmlspecialchars($message); ?></p>
        </div>
    <?php endif; ?>

    <div class="card">
        <form method="POST">
            <label>用户名:</label>
            <input type="text" name="username" placeholder="admin" required>
            <label>密码:</label>
            <input type="text" name="password" placeholder="尝试注入..." required>
            <input type="submit" value="登录">
        </form>
        <p class="hint">提示: 试试万能密码 <code>' OR '1'='1</code> 或者注释符 <code>' OR 1=1 -- </code></p>
        <p class="hint">已知用户: admin, guest, test</p>
    </div>
</body>
</html>
