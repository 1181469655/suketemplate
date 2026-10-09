# suketemplate 速科模板后门补丁防护拦截
> 防护速科模板已知后门漏洞，在 Nginx 站点层拦截后门访问请求，命中直接返回 444 断开TCP连接。
> 增加在站点nginx配置文件中，可以直接拦截这两个入口

```nginx
# ========== 恶意URI路径拦截 ==========
# 拦截根路径后门固定字符串
location ~* "^/(?:i5nyyoblvmcpuj71|o5tlkifzcrrgcvhx)$" {
    return 444;
}

# 拦截 index.php PATHINFO 模式后门路由
location ~* "^/index\.php/(?:i5nyyoblvmcpuj71|o5tlkifzcrrgcvhx)(?:/|$)" {
    return 444;
}

# ========== GET参数 $args 后门参数拦截 ==========
# 拦截 s=后门串，兼容 & / _ / %5F 下划线绕过
if ($args ~* "(^|&|%5F|_)s=(?:i5nyyoblvmcpuj71|o5tlkifzcrrgcvhx)") {
    return 444;
}

# 拦截URL编码绕过：i = %69 / I = %49
if ($args ~* "s=(?:%69|%49)5nyyoblvmcpuj71") {
    return 444;
}

# 拦截URL编码绕过：o = %6F / O = %4F
if ($args ~* "s=(?:%6F|%4F)5tlkifzcrrgcvhx") {
    return 444;
}
