# SUI API 文档（中文）

基础地址：`http://<host>:<port>`

> 大多数接口需要登录后携带：`Authorization: Bearer <token>`。

## 认证

### POST `/auth/login`
面板登录。

请求示例：
{
  "username": "admin",
  "password": "admin123"
}

成功响应示例：
{
  "success": true,
  "token": "...",
  "user": "admin",
  "mustReset": false,
  "panelPath": "/"
}

### POST `/auth/logout`
退出当前会话。

### GET `/auth/me`
校验当前 token / 会话状态。

---

## 面板设置

### GET `/api/panel/settings`
获取面板基础设置。

### POST `/api/panel/settings`
更新用户名 / panelPath。

### POST `/api/panel/change-password`
修改面板密码。

### GET `/api/panel/token`
获取当前面板 API Token。

### POST `/api/panel/token/rotate`
轮换（重置）面板 API Token。

### POST `/api/panel/connect-sub`
一键把当前面板 URL + Token 写入 `sui-sub`。

请求字段：`subUrl`、`subUsername`、`subPassword`、`sourceName(可选)`。

---

## 入站（Inbounds）

- GET `/api/inbounds`：列表
- GET `/api/inbounds/next-port`：建议可用端口
- POST `/api/inbounds/add`：新增
- POST `/api/inbounds/add-reality-quick`：一键新增 Reality
- PUT `/api/inbounds/:id`：更新（基础字段）
- PUT `/api/inbounds/:id/full`：更新（完整字段）
- POST `/api/inbounds/:id/toggle`：启用/禁用
- DELETE `/api/inbounds/:id`：删除
- POST `/api/inbounds/batch-toggle`：批量启停
- GET `/api/inbounds/:id/links`：获取节点链接
- GET `/api/inbounds/:id/qr`：获取二维码信息

---

## 端口转发（Forwards）

- GET `/api/forwards`：列表
- POST `/api/forwards`：新增
- PUT `/api/forwards/:id`：更新
- POST `/api/forwards/:id/toggle`：启用/禁用
- DELETE `/api/forwards/:id`：删除

---

## 系统与运行状态

- GET `/api/health`：健康检查
- GET `/api/view/bootstrap`：前端初始化数据
- GET `/api/system/status`：面板 + Xray 状态摘要
- POST `/api/system/restart-panel`：重启面板
- POST `/api/system/restart-xray`：重启 Xray
- POST `/api/system/restart-xui`：兼容重启入口
- POST `/api/system/chain/test`：链式代理连通性测试
- POST `/api/system/optimize/bbr`：开启 BBR + fq
- POST `/api/system/optimize/dns`：DNS 优化
- POST `/api/system/optimize/sysctl`：sysctl 优化
- POST `/api/system/optimize/all`：一键全部优化

---

## Xray 工具接口

- GET `/api/system/xray/version-current`：当前版本信息
- GET `/api/system/xray/versions`：可切换版本列表
- POST `/api/system/xray/switch`：切换版本
- GET `/api/system/xray/reality-gen`：生成 Reality 密钥/shortid
- GET `/api/system/xray/config`：读取配置文本
- POST `/api/system/xray/config`：保存配置文本

---

## 通用错误格式

{
  "success": false,
  "msg": "错误信息"
}

状态码语义遵循常规 HTTP（`400/401/403/404/500`）。
