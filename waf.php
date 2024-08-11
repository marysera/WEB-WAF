<?php

// 文件路径
$blacklistFile = '/tmp/waf/blacklist.txt';
$keywordsFile = '/tmp/waf/keywords.txt';
$accessFile = '/tmp/waf/access_log_' . $ip . '.txt';

// 创建访问日志文件
if (!file_exists($accessFile)) {
    file_put_contents($accessFile, '');
}

// 读取黑名单
$blacklistedIps = file($blacklistFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

// 检查是否在黑名单中
if (in_array($ip, $blacklistedIps)) {
    // 如果 IP 在黑名单中，禁止访问
    header('Location: http://127.0.0.1');
    exit;
}

// 获取访问的目录或页面
$requestUri = $_SERVER['REQUEST_URI'];

// 获取当前时间
$timestamp = date('Y-m-d H:i:s');

// 读取威胁关键词
$dangerousKeywords = file($keywordsFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
$isDangerous = false;

foreach ($dangerousKeywords as $keyword) {
    if (stripos($requestUri, $keyword) !== false || stripos(file_get_contents('php://input'), $keyword) !== false) {
        $isDangerous = true;
        break;
    }
}

// 如果检测到危险关键词，则记录并阻止访问
if ($isDangerous) {
    // 将 IP 地址记录到黑名单文件
    file_put_contents($blacklistFile, $ip . PHP_EOL, FILE_APPEND);

    // 记录访问信息到 access_log.txt
    $entry = sprintf("%s - %s%s - %s - WARNING: Dangerous content detected\n", $timestamp, $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'], $requestUri, $ip);
    file_put_contents($accessLogFile, $entry, FILE_APPEND);

    // 禁止访问
    header('Location: http://127.0.0.1');
    exit;
}

// 读取访问记录
$accessLog = file_get_contents($accessFile);
$accessTimes = explode("\n", trim($accessLog));
$now = time();

// 过滤掉过期的访问记录
$recentAccessTimes = array_filter($accessTimes, function($time) use ($now) {
    return ($now - $time) < 60; // 只保留过去60秒的记录
});

// 如果访问次数超过x次，记录到黑名单文件
if (count($recentAccessTimes) >= 30) {
    file_put_contents($blacklistFile, $ip . "\n", FILE_APPEND);
    header('Location: http://127.0.0.1');
    exit(); // 确保脚本在重定向后不再执行
}

// 更新访问记录
$recentAccessTimes[] = $now;
file_put_contents($accessFile, implode("\n", $recentAccessTimes));

// 记录正常访问
$entry = sprintf("%s - %s%s - %s\n", $timestamp, $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'], $requestUri, $ip);
file_put_contents($accessLogFile, $entry, FILE_APPEND);

?>
