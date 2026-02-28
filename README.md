# SUI Panel 苏逸面板 🚀

SUI Panel 是一个面向真实运维场景的 Xray 管理面板，目标很直接：
- **安装简单**：一条命令即可部署
- **维护省心**：内置菜单可直接改账号、改端口、更新版本
- **状态清晰**：服务状态、版本信息、端口监听一眼可见
- **数据可控**：核心配置与面板数据都落在固定路径，便于备份与迁移

适合想要“快速上线 + 稳定长期用”的 VPS 用户。✨

## ✨ 功能

- Web 面板登录与会话管理
- 入站（Inbounds）管理
- 自动生成并维护 Xray 配置
- systemd 服务联动管理（`sui-panel.service` / `sui-xray-core.service`）
- 节点链接与二维码生成
- 链式代理（单节点绑定 1 个下游：`http` / `socks5` / `reality(vless)` / `shadowsocks`）
- 下游连通性测试（面板内一键测试 host/port）
- 域名分流增强模式（后端自动写路由，无需手改配置）

## ⚡ 一键安装（推荐）

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/sui/main/install.sh)
```

> 安装器已固定为二进制模式（不再走 Docker 安装流程）。

## 🧭 安装后常用命令

```bash
sui
```

在菜单里可直接：
- 修改用户名/密码
- 修改端口
- 更新 SUI
- 查看服务状态与版本

## 🧩 主要文件是干什么的

- `install.sh`：一键安装/更新入口（拉取二进制、写 systemd、初始化环境）
- `server.mjs`：后端核心逻辑（登录鉴权、节点管理、状态查询、转发 API）
- `public/index.html`：前端页面（面板 UI + 调用后端 API）
- `dist/sui-panel-full-linux-amd64`：最终可执行二进制（生产环境主要运行这个）
- `README.md`：使用说明文档

## 🗂️ 关键路径

- 面板程序目录：`/opt/sui-panel`
- 环境变量：`/etc/default/sui-panel`
- 面板数据：`/opt/sui-panel/inbounds.json`
- 转发数据：`/opt/sui-panel/forwards.json`
- 面板设置：`/opt/sui-panel/panel-settings.json`
- Xray 配置：`/etc/sui-xray/config.json`

## 🔀 链式代理与域名分流（新）

在“节点管理 → 编辑节点”里可直接配置，不需要手改 Xray 配置文件：

- 开启“链式代理”后，绑定 1 个下游节点（`http` / `socks5` / `reality(vless)` / `shadowsocks`）
- 可填写“域名规则”：
  - `example.com` → 匹配根域 + 子域
  - `api.example.com` → 精确匹配该子域
  - `.example.com` → 子域泛匹配
- 多域名支持两种分隔：
  - 逗号：`example.com,api.example.com,.demo.net`
  - 换行：一行一个
- 开启“域名分流增强（推荐）”后，后端会自动：
  - 开启入站 sniff 路由增强
  - 设置 `domainStrategy=IPIfNonMatch`
  - 应用 UDP/443 策略（默认拦截，减少 QUIC 绕过）

## 🔐 注意事项

- 首次部署后请立即修改默认账号密码
- 生产环境建议限制面板访问来源（防火墙/安全组）
- 更新后若页面异常，先强刷浏览器缓存（Ctrl+F5）

---

Made with 🛠️ by Spittingjiu
