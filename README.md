<h1>新一代轻量化网页软WAF</h1>

只建议小型博客网站使用 

当前版本 1.2.1

更新日志：<a href="https://xn--ivr.net/index.php/archives/waf.html" rel="nofollow">点击查看</a>

<h2>介绍:</h2>

支持web管理 黑名单 白名单 IP限制 

支持关键字过滤(需要自行选择)

支持防御轻量DDOS

<h2>使用说明:</h2>

下载后立刻更改admin.php里的用户名和密码

在tmp目录里创建两个文件夹

```sh
sudo mkdir /tmp/waf
sudo mkdir /tmp/waf/log
sudo chmod 777 /tmp/waf/*
```

定期清理 /tmp/waf 里的文件

waf.php不要放在网站根目录

将下面代码插入到网站的index.php的最前面


```php
<?php
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
$whitelistFile = '/tmp/waf/whitelist.txt';
$accessLogFile = '/tmp/waf/access_log.txt';
$whitelistedIps = file($whitelistFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

if (!file_exists($whitelistFile)) {
    file_put_contents($whitelistFile, '');
}
// 检查是否在白名单中
if (in_array($ip, $whitelistedIps)) {
    // 如果 IP 在白名单中，允许访问
    $timestamp = date('Y-m-d H:i:s');
    $entry = sprintf("%s - %s%s - %s - WHITELISTED\n", $timestamp, $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'], $ip);
    file_put_contents($accessLogFile, $entry, FILE_APPEND);
    //echo "Access allowed.";

}
else{
    include '/存放的目录/waf.php'; 
}
?>
```

如果没有权限
需要自己在/tmp/waf/里创建3个文件 whitelist.txt blacklist.txt keywords.txt