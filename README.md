# SUI Panel 苏逸面板

**一个面向 VPS 运维场景的轻量级 Xray 管理面板。**

SUI 的目标很直接：
- 安装简单
- 运维省心
- 节点管理直观
- 可和 `sui-sub` 无缝联动做订阅分发

---

## Quick Overview

| 能力 | 是否支持 |
|---|:---:|
| 一键安装（脚本） | ✅ |
| 菜单化运维（改账号/端口/SSL/卸载） | ✅ |
| 节点管理（新增/编辑/删除/开关） | ✅ |
| 节点链接与二维码导出 | ✅ |
| 链式代理（http/socks5/reality/ss） | ✅ |
| 域名分流增强（自动路由策略） | ✅ |
| 与 `sui-sub` 一键对接 | ✅ |
| 原生 HTTPS（申请证书 + 面板 TLS） | ✅ |

---

## 适合谁？

适合：
- 想在 VPS 上快速搭建并长期维护 Xray
- 希望通过菜单完成常见运维操作
- 有多机节点，需要后续接入 `sui-sub` 做统一订阅

不适合：
- 需要超复杂企业级多租户权限系统

---

## 快速安装

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/Spittingjiu/sui/main/install.sh)
```

安装完成后执行：

```bash
sui
```

进入菜单即可管理。

---

## 默认安装信息

- 面板端口：`8810`
- 默认账号：`admin`
- 默认密码：`admin123`

> 建议首次登录后立即修改账号密码。

---

## 常用菜单能力

- 修改面板账号密码
- 显示当前用户信息（用户名/密码/端口/协议）
- 修改面板端口
- 启用 BBR + fq
- 一键 SSL（证书申请 + Xray TLS + 面板原生 HTTPS）
- 一键卸载
- 一键对接 `sui-sub`

---

## 与 sui-sub 联动（推荐）

在 SUI 的「对接Token」页可直接填写：
- `sui-sub` 地址
- `sui-sub` 用户名
- `sui-sub` 密码
- （可选）源名称

点击后会自动将当前 SUI 面板地址和 Token 写入 `sui-sub`，免手工复制。

---

## 关键路径

- 程序目录：`/opt/sui-panel`
- 环境变量：`/etc/default/sui-panel`
- 面板数据：`/opt/sui-panel/data/inbounds.json`
- 转发数据：`/opt/sui-panel/data/forwards.json`
- 面板设置：`/opt/sui-panel/data/panel-settings.json`
- Xray 配置：`/etc/sui-xray/config.json`

---

## 运维建议

- 上线后限制面板访问来源（防火墙/安全组）
- 定期备份 `/opt/sui-panel/data` 与 `/etc/sui-xray/config.json`
- 升级后若页面异常，先强制刷新浏览器缓存

---

## Sprint A 冒烟检查（推荐）

新增了发布前快速检查脚本：

```bash
PANEL_BASE=http://127.0.0.1:12345 \
PANEL_USER=admin \
PANEL_PASS=admin123 \
bash scripts/sprint-a-smoke.sh
```

脚本会检查：
- 登录
- Token 接口
- Bootstrap 接口

通过后再发布，可降低回归风险。

---

## 生态项目

- SUI：节点管理层（本项目）
- sui-sub：订阅编排与分发层  
  https://github.com/Spittingjiu/sui-sub

---

## API Documentation

- English: `docs/API.md`
- 中文：`docs/API.zh-CN.md`

## License

GPL-3.0
