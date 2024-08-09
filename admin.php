<?php
session_start();

// 获取真实 IP 地址的函数
function getRealIpAddr() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    if (strpos($ip, ',') !== false) {
        $ip = explode(',', $ip)[0];
    }

    return trim($ip);
}

// 获取真实 IP 地址
$ip = getRealIpAddr();

// 文件路径
$whitelistFile = '/tmp/waf/whitelist.txt';
$blacklistFile = '/tmp/waf/blacklist.txt';
$accessLogFile = '/tmp/waf/access_log.txt';
$keywordsFile = '/tmp/waf/keywords.txt';

// 加载白名单、黑名单和关键词文件
$whitelistedIps = [];
if (file_exists($whitelistFile)) {
    $whitelistedIps = file($whitelistFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
}

$blacklistedIps = [];
if (file_exists($blacklistFile)) {
    $blacklistedIps = file($blacklistFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
}

$dangerousKeywords = [];
if (file_exists($keywordsFile)) {
    $dangerousKeywords = file($keywordsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
}


// 检查是否在黑名单中
if (in_array($ip, $blacklistedIps)) {
    header('Location: http://127.0.0.1');
    exit;
}



// 登录验证
function checkLogin($username, $password) {
    $users = [
        'admin' => password_hash('password123', PASSWORD_DEFAULT), // 使用密码哈希
    ];
    
    return isset($users[$username]) && password_verify($password, $users[$username]);
}



// 处理登录
if (isset($_POST['login'])) {
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    if (checkLogin($username, $password)) {
        $_SESSION['loggedin'] = true;
        header('Location: ' . $_SERVER['PHP_SELF']);
        exit;
    } else {
        $loginError = '用户名或密码错误';
    }
}

// 处理登出
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}

// 如果用户没有登录
if (!isset($_SESSION['loggedin'])) {
    $showLoginForm = true;
} else {
    $showLoginForm = false;


// 记录访问信息
$timestamp = date('Y-m-d H:i:s');
$requestUri = $_SERVER['REQUEST_URI'];
$logMessage = "$timestamp - " . $_SERVER['REQUEST_METHOD'] . " " . $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'] . $requestUri . " - $ip\n";

// 检查是否在白名单中
$isWhitelisted = in_array($ip, $whitelistedIps);

// 检查是否在黑名单中
$isBlacklisted = in_array($ip, $blacklistedIps);

// 如果不在白名单中且在黑名单中，执行安全检查
if (!$isWhitelisted) {
// 检查是否包含危险关键词
    $isDangerous = false;
        foreach ($dangerousKeywords as $keyword) {
            if (stripos($requestUri, $keyword) !== false || stripos(file_get_contents('php://input'), $keyword) !== false) {
                $isDangerous = true;
                break;
            }
        }

        // 如果检测到危险内容
        if ($isDangerous) {
            file_put_contents($blacklistFile, $ip . PHP_EOL, FILE_APPEND);
            // 记录访问信息到 access_log.txt
            $entry = sprintf("%s - %s%s - %s - WARNING: Dangerous content detected\n", $timestamp, $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'], $requestUri, $ip);
            file_put_contents($accessLogFile, $entry, FILE_APPEND);

            // 禁止访问
            header('Location: http://127.0.0.1');
            exit;
        }
    }

    // 写入访问日志
    if (!empty($logMessage)) {
        file_put_contents($accessLogFile, $logMessage, FILE_APPEND | LOCK_EX);
    }
}

// 手动添加和删除白名单功能
if (isset($_POST['addWhitelist'])) {
    $ipToAdd = trim($_POST['ipToAdd']);
    if (filter_var($ipToAdd, FILTER_VALIDATE_IP)) {
        file_put_contents($whitelistFile, $ipToAdd . PHP_EOL, FILE_APPEND | LOCK_EX);
        $statusMessage = "IP 地址 $ipToAdd 已添加到白名单。";
    } else {
        $statusMessage = "无效的 IP 地址。";
    }
}

if (isset($_POST['removeWhitelist'])) {
    $ipToRemove = trim($_POST['ipToRemove']);
    if (filter_var($ipToRemove, FILTER_VALIDATE_IP)) {
        // 从白名单数组中移除指定 IP
        $whitelistedIps = array_filter($whitelistedIps, function($item) use ($ipToRemove) {
            return trim($item) !== $ipToRemove;
        });

        // 重新写入白名单文件
        file_put_contents($whitelistFile, implode(PHP_EOL, $whitelistedIps) . PHP_EOL);
        $statusMessage = "IP 地址 $ipToRemove 已从白名单中移除。";
    } else {
        $statusMessage = "无效的 IP 地址。";
    }
}

// 手动添加和删除黑名单功能
if (isset($_POST['addBlacklist'])) {
    $ipToAdd = trim($_POST['ipToAdd']);
    if (filter_var($ipToAdd, FILTER_VALIDATE_IP)) {
        file_put_contents($blacklistFile, $ipToAdd . PHP_EOL, FILE_APPEND | LOCK_EX);
        $statusMessage = "IP 地址 $ipToAdd 已添加到黑名单。";
    } else {
        $statusMessage = "无效的 IP 地址。";
    }
}

if (isset($_POST['removeBlacklist'])) {
    $ipToRemove = trim($_POST['ipToRemove']);
    if (filter_var($ipToRemove, FILTER_VALIDATE_IP)) {
        // 从黑名单数组中移除指定 IP
        $blacklistedIps = array_filter($blacklistedIps, function($item) use ($ipToRemove) {
            return trim($item) !== $ipToRemove;
        });

        // 重新写入黑名单文件
        file_put_contents($blacklistFile, implode(PHP_EOL, $blacklistedIps) . PHP_EOL);
        $statusMessage = "IP 地址 $ipToRemove 已从黑名单中移除。";
    } else {
        $statusMessage = "无效的 IP 地址。";
    }
}

// 添加危险关键词
if (isset($_POST['addKeyword'])) {
    $keywordToAdd = trim($_POST['keywordToAdd']);
    if (!empty($keywordToAdd)) {
        file_put_contents($keywordsFile, $keywordToAdd . PHP_EOL, FILE_APPEND | LOCK_EX);
        $statusMessage = "关键词 '$keywordToAdd' 已添加到危险关键词列表。";
    } else {
        $statusMessage = "无效的关键词。";
    }
}

// 删除危险关键词
if (isset($_POST['removeKeyword'])) {
    $keywordToRemove = trim($_POST['keywordToRemove']);
    if (!empty($keywordToRemove)) {
        // 从危险关键词数组中移除指定关键词
        $dangerousKeywords = array_filter($dangerousKeywords, function($item) use ($keywordToRemove) {
            return trim($item) !== $keywordToRemove;
        });

        // 重新写入危险关键词文件
        file_put_contents($keywordsFile, implode(PHP_EOL, $dangerousKeywords) . PHP_EOL);
        $statusMessage = "关键词 '$keywordToRemove' 已从危险关键词列表中移除。";
    } else {
        $statusMessage = "无效的关键词。";
    }
}

// 清空 IP 记录
if (isset($_POST['clearIpRecords'])) {
    file_put_contents($accessLogFile, '');
    $statusMessage = "IP 记录已清空。";
}

// 计算访问日志行数
$logLineCount = 0;
if (file_exists($accessLogFile)) {
    $logLineCount = count(file($accessLogFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES));
}
?>

<!DOCTYPE html>
<html lang="zh">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SHERRY'S 网页WAF 1.0</title>
    <link rel="shortcut icon" href="https://cdn.xn--ivr.net/image/tx/favicon.ico" /> 
    <style>
        body {
            font-family: 'Arial', sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f0f4f8;
            color: #333;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            background-image: url('https://cdn.xn--ivr.net/image/sherry.php');
            background-size: cover;
            background-position: center;
            background-repeat: no-repeat;
            background-attachment: fixed; /* 确保背景图片在滚动时不会移动 */
        }
        .container {
            width: 90%;
            max-width: 1000px;
            background: rgba(255, 255, 255, 0.9);
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            padding: 20px;
            box-sizing: border-box;
        }
        .header {
            text-align: center;
            margin-bottom: 20px;
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
            color: #007bff;
        }
        .form-section {
            margin-bottom: 20px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background: #fff;
        }
        .form-section h2 {
            margin-top: 0;
            font-size: 24px;
            color: #007bff;
        }
        .form-section input[type="text"],
        .form-section input[type="password"],
        .form-section input[type="submit"] {
            width: calc(100% - 22px);
            padding: 10px;
            margin: 8px 0;
            box-sizing: border-box;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 16px;
        }
        .form-section input[type="submit"] {
            background-color: #007bff;
            border: none;
            color: white;
            cursor: pointer;
            font-weight: bold;
        }
        .form-section input[type="submit"]:hover {
            background-color: #0056b3;
        }
        .logs-section {
            margin-bottom: 20px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background: #fff;
            max-height: 300px;
            overflow-y: auto;
        }
        .logs-section h2 {
            margin-top: 0;
            font-size: 24px;
            color: #007bff;
        }
        .logs-section pre {
            white-space: pre-wrap;
            font-size: 14px;
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            line-height: 1.4;
        }
        .logs-section pre code {
            display: block;
            margin: 0;
            padding: 0;
            font-size: 14px;
            background-color: #f8f9fa;
            border-radius: 4px;
        }
        .logs-section pre code span {
            display: inline-block;
            padding: 0 5px;
            margin: 0 2px;
            background-color: #ffcccb;
            border-radius: 2px;
        }
        .status-message {
            padding: 10px;
            margin: 10px 0;
            border-radius: 4px;
            color: #fff;
        }
        .status-message.success {
            background-color: #28a745;
        }
        .status-message.error {
            background-color: #dc3545;
        }
        @media (max-width: 768px) {
            .container {
                width: 100%;
                border-radius: 0;
            }
        }
        .link-container {
            text-align: center;
        }
        .jump-link {
            display: inline-block;
            padding: 10px 20px;
            margin: 10px;
            text-decoration: none;
            color: #fff;
            background-color: #007bff;
            border-radius: 5px;
            font-size: 16px;
        }
        .jump-link:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>SHERRY'S 网页WAF 1.0</h1>
        </div>

        <?php if ($showLoginForm): ?>
            <div class="form-section">
                <h2>管理员登录</h2>
                <?php if (isset($loginError)): ?>
                    <div class="status-message error"><?php echo $loginError; ?></div>
                <?php endif; ?>
                <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
                    <input type="text" name="username" placeholder="用户名" required><br>
                    <input type="password" name="password" placeholder="密码" required><br>
                    <input type="submit" name="login" value="登录">
                </form>
            </div>
        <?php else: ?>
            <?php if (isset($statusMessage)): ?>
                <div class="status-message success"><?php echo $statusMessage; ?></div>
            <?php endif; ?>
            <!-- 使用说明 -->
            <div class="form-section">
                <h2>使用说明</h2>
            </br>
            <iframe src="https://marysera.github.io/waf/index.html" width="100%" height="500"></iframe>
            </br>
            <div class="link-container">
            <a href="https://xn--ivr.net/index.php/archives/waf.html" class="jump-link">官网</a>
            <a href="https://github.com/marysera/SHERRY-S-WAF" class="jump-link">访问Github</a>
            </div>

            </div>
            <!-- 刷新页面 -->
            <div class="form-section">
                <h2>刷新页面</h2>
                <form action="" method="get">
                    <input type="submit" value="刷新页面">
                </form>
            </div>
            <div class="form-section">
                <h2>添加到白名单</h2>
                <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
                    <input type="text" name="ipToAdd" placeholder="要添加到白名单的 IP 地址" required><br>
                    <input type="submit" name="addWhitelist" value="添加到白名单">
                </form>
            </div>

            <div class="form-section">
                <h2>移除白名单中的 IP 地址</h2>
                <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
                    <input type="text" name="ipToRemove" placeholder="要移除的白名单中的 IP 地址" required><br>
                    <input type="submit" name="removeWhitelist" value="从白名单中移除">
                </form>
            </div>

            <div class="logs-section">
                <h2>当前白名单内容</h2>
                <pre><code><?php echo implode(PHP_EOL, $whitelistedIps); ?></code></pre>
            </div>

            <div class="form-section">
                <h2>添加到黑名单</h2>
                <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
                    <input type="text" name="ipToAdd" placeholder="要添加到黑名单的 IP 地址" required><br>
                    <input type="submit" name="addBlacklist" value="添加到黑名单">
                </form>
            </div>

            <div class="form-section">
                <h2>移除黑名单中的 IP 地址</h2>
                <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
                    <input type="text" name="ipToRemove" placeholder="要移除的黑名单中的 IP 地址" required><br>
                    <input type="submit" name="removeBlacklist" value="从黑名单中移除">
                </form>
            </div>

            <div class="logs-section">
                <h2>当前黑名单内容</h2>
                <pre><code><?php echo implode(PHP_EOL, $blacklistedIps); ?></code></pre>
            </div>

            <div class="form-section">
                <h2>添加危险关键词</h2>
                <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
                    <input type="text" name="keywordToAdd" placeholder="要添加的危险关键词" required><br>
                    <input type="submit" name="addKeyword" value="添加关键词">
                </form>
            </div>

            <div class="form-section">
                <h2>移除危险关键词</h2>
                <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
                    <input type="text" name="keywordToRemove" placeholder="要移除的危险关键词" required><br>
                    <input type="submit" name="removeKeyword" value="移除关键词">
                </form>
            </div>

            <div class="logs-section">
                <h2>当前危险关键词</h2>
                <pre><code><?php echo implode(PHP_EOL, $dangerousKeywords); ?></code></pre>
            </div>

            <div class="form-section">
                <h2>清空 IP 记录</h2>
                <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="post">
                    <input type="submit" name="clearIpRecords" value="清空 IP 记录">
                    <span></br>当前日志行数: <?php echo $logLineCount; ?></span>
                </form>
            </div>

            <div class="logs-section">
                <h2>访问日志</h2>
                <?php if (file_exists($accessLogFile)): ?>
                    <pre><code><?php echo htmlspecialchars(file_get_contents($accessLogFile)); ?></code></pre>
                <?php else: ?>
                    <p>暂无访问日志。</p>
                <?php endif; ?>
            </div>

            <div class="form-section">
                <h2>退出登录</h2>
                <form action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="get">
                    <input type="submit" name="logout" value="退出登录">
                </form>
            </div>

        <?php endif; ?>
    </div>
</body>
</html>

