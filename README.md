# SUI Panel

纯自研的 Xray 管理面板（不依赖 x-ui API），提供 Web 管理、节点增删改查、配置落盘与核心服务联动。

## 功能概览

- Web 面板登录与会话管理
- 入站（inbounds）管理
- 自动生成并维护 Xray 配置
- 通过 systemd 管理核心服务（`cui-xray-core.service`）
- 支持二维码生成

## 项目结构

- `server.mjs`：后端主程序（Express）
- `public/`：前端静态资源
- `dist/`：发布产物（含全功能二进制）
- `install.sh`：一键安装脚本

## 运行要求

- Linux（建议 Debian/Ubuntu）
- Node.js 18+
- root 权限（需要写入 `/etc`、`/opt` 并管理 systemd）
- systemd

## 本地开发运行

```bash
npm install
node server.mjs
```

默认端口：`8810`

可用环境变量：

- `PORT`：面板监听端口（默认 `8810`）
- `PANEL_TOKEN`：面板 token（默认随机生成）
- `PANEL_USER`：初始用户名（默认 `admin`）
- `PANEL_PASS`：初始密码（默认 `admin123`）
- `PANEL_PATH`：面板路径（默认 `/`）
- `XRAY_PUBLIC_HOST`：对外主机名
- `PANEL_SERVICE`：面板服务名（默认 `sui-panel.service`）

## 生产部署（推荐）

使用项目内安装脚本：

```bash
bash install.sh
```

安装后可配合 Nginx 做反向代理，并启用 HTTPS。

## 数据与配置路径

- 面板数据目录：`/opt/cui-panel`
- 入站数据：`/opt/cui-panel/inbounds.json`
- 面板设置：`/opt/cui-panel/panel-settings.json`
- Xray 配置：`/etc/cui-xray/config.json`

## 注意事项

- 首次部署请及时修改默认账号密码
- 生产环境建议开启防火墙并限制管理面板访问来源
- 对外发布前请确认端口与证书配置正确

## License

暂未指定（默认保留所有权利）。
