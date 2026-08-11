<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <title>SQL 注入练习平台</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; max-width: 800px; margin: 50px auto; background: #1a1a2e; color: #e0e0e0; }
        h1 { color: #e94560; }
        a { color: #0f3460; background: #e94560; padding: 8px 16px; text-decoration: none; border-radius: 4px; display: inline-block; margin: 5px; }
        a:hover { background: #c23152; }
        .card { background: #16213e; border-radius: 8px; padding: 20px; margin: 15px 0; }
        code { background: #0f3460; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>🔓 SQL 注入练习平台</h1>
    <p>以下练习环境仅供学习使用，请勿用于非法用途。</p>

    <div class="card">
        <h3>1. 数字型注入 (GET)</h3>
        <p>参数 <code>?id=1</code>，注入点：数字型 <code>WHERE id=</code></p>
        <a href="sql1.php?id=1">sql1.php</a>
    </div>

    <div class="card">
        <h3>2. 字符型注入 (GET)</h3>
        <p>参数 <code>?id=1</code>，注入点：字符型 <code>WHERE id=''</code></p>
        <a href="sql2.php?id=1">sql2.php</a>
    </div>

    <div class="card">
        <h3>3. 登录绕过 (POST)</h3>
        <p>万能密码登录，绕过认证</p>
        <a href="login.php">login.php</a>
    </div>

    <div class="card">
        <h3>4. 搜索型注入 (GET)</h3>
        <p>参数 <code>?q=新闻</code>，注入点：LIKE 查询 <code>WHERE title LIKE '%xxx%'</code></p>
        <a href="search.php?q=新闻">search.php</a>
    </div>

    <div class="card">
        <h3>5. 联合查询注入 (GET)</h3>
        <p>参数 <code>?id=1</code>，练习 UNION SELECT 爆数据</p>
        <a href="union.php?id=1">union.php</a>
    </div>
</body>
</html>
