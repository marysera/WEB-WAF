<h1>新一代轻量化网页软WAF</h1>

只建议小型博客网站使用

博客主页:https://xn--ivr.net/

使用说明:

下载后立刻更改admin.php里的用户名和密码

在tmp目录里创建一个文件夹
sudo mkdir /tmp/waf
sudo chmod 777 /tmp/waf


将下面一段插入到网站的index.php的最前面

'''
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

// 检查是否在白名单中
if (in_array($ip, $whitelistedIps)) {
    // 如果 IP 在白名单中，允许访问
    $timestamp = date('Y-m-d H:i:s');
    $entry = sprintf("%s - %s%s - %s - WHITELISTED\n", $timestamp, $_SERVER['REQUEST_SCHEME'] . '://' . $_SERVER['HTTP_HOST'], $_SERVER['REQUEST_URI'], $ip);
    file_put_contents($accessLogFile, $entry, FILE_APPEND);
    //echo "Access allowed.";

}
else{
    include 'waf.php'; 
}
'''