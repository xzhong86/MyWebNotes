# Apache + Let's Encrypt 部署笔记（notes 子域名）

适用场景：

- 现有 Apache 服务继续保留（不迁移到 Caddy）
- 新增 `notes` 子域名反向代理到本项目 Node 服务
- 使用 Let's Encrypt 证书，保证 `https` 可用（解决 `crypto.subtle` 不可用问题）

## 1. 前置条件

- 域名已解析到服务器公网 IP（例如：`notes.example.com`）
- Node 服务已启动并监听 `127.0.0.1:8080`
- Apache 正常运行中

## 2. 启用 Apache 模块

```bash
sudo a2enmod proxy proxy_http ssl headers rewrite
sudo systemctl reload apache2
```

## 3. 新增 notes 子域名虚拟主机

创建文件：

`/etc/apache2/sites-available/notes.example.com.conf`

内容示例：

```apache
<VirtualHost *:80>
    ServerName notes.example.com

    ProxyPreserveHost On
    ProxyPass / http://127.0.0.1:8080/
    ProxyPassReverse / http://127.0.0.1:8080/

    ErrorLog ${APACHE_LOG_DIR}/notes-error.log
    CustomLog ${APACHE_LOG_DIR}/notes-access.log combined
</VirtualHost>
```

## 4. 启用站点并检查配置

```bash
sudo a2ensite notes.example.com.conf
sudo apachectl configtest
sudo systemctl reload apache2
```

## 5. 申请并配置 Let's Encrypt 证书

```bash
sudo apt install -y certbot python3-certbot-apache
sudo certbot --apache -d notes.example.com
```

执行时建议选择自动重定向到 HTTPS。

## 6. 验证

- 访问：`https://notes.example.com`
- 浏览器应显示安全锁
- 解锁页不再报错：`crypto.subtle.importKey` undefined

## 7. 排障命令

```bash
sudo apachectl configtest
sudo systemctl status apache2 --no-pager -l
sudo tail -n 100 /var/log/apache2/notes-error.log
sudo tail -n 100 /var/log/apache2/notes-access.log
```

## 8. 说明

- 该方案不会影响现有 Apache 其他站点，只是新增一个 vhost。
- 若后续更换 Node 端口，只需同步更新 `ProxyPass/ProxyPassReverse`。
