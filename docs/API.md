# SUI API Documentation

Base URL: `http://<host>:<port>`

> Most APIs require `Authorization: Bearer <token>` obtained from login.

## Auth

### POST `/auth/login`
Login panel account.

Request:
```json
{ "username": "admin", "password": "admin123" }
```
Response (success):
```json
{ "success": true, "token": "...", "user": "admin", "mustReset": false, "panelPath": "/" }
```

### POST `/auth/logout`
Logout current session.

### GET `/auth/me`
Validate current token/session.

---

## Panel Settings

### GET `/api/panel/settings`
Get panel basic settings.

### POST `/api/panel/settings`
Update username/panelPath.

### POST `/api/panel/change-password`
Change panel password.

### GET `/api/panel/token`
Get current panel API token.

### POST `/api/panel/token/rotate`
Rotate panel API token.

### POST `/api/panel/connect-sub`
One-click push current panel URL + token to `sui-sub`.

Request:
```json
{
  "subUrl": "https://sub.example.com",
  "subUsername": "admin",
  "subPassword": "***",
  "sourceName": "my-sui"
}
```

---

## Inbounds

### GET `/api/inbounds`
List all inbounds.

### GET `/api/inbounds/next-port`
Get suggested next free port.

### POST `/api/inbounds/add`
Create inbound.

### POST `/api/inbounds/add-reality-quick`
Quick create Reality inbound.

### PUT `/api/inbounds/:id`
Update inbound (basic fields).

### PUT `/api/inbounds/:id/full`
Update inbound (full payload).

### POST `/api/inbounds/:id/toggle`
Enable/disable inbound.

### DELETE `/api/inbounds/:id`
Delete inbound.

### POST `/api/inbounds/batch-toggle`
Batch toggle inbounds.

### GET `/api/inbounds/:id/links`
Get generated subscription links for inbound.

### GET `/api/inbounds/:id/qr`
Get QR info/data URL for inbound.

---

## Forwards

### GET `/api/forwards`
List forward rules.

### POST `/api/forwards`
Create forward rule.

### PUT `/api/forwards/:id`
Update forward rule.

### POST `/api/forwards/:id/toggle`
Enable/disable forward rule.

### DELETE `/api/forwards/:id`
Delete forward rule.

---

## System / Runtime

### GET `/api/health`
Health check.

### GET `/api/view/bootstrap`
Bootstrap payload for frontend.

### GET `/api/system/status`
Panel + Xray status summary.

### POST `/api/system/restart-panel`
Restart panel service.

### POST `/api/system/restart-xray`
Restart xray core service.

### POST `/api/system/restart-xui`
Compatibility restart endpoint.

### POST `/api/system/chain/test`
Test chain proxy connectivity.

### POST `/api/system/optimize/bbr`
Enable BBR+fq optimization.

### POST `/api/system/optimize/dns`
Apply DNS optimization.

### POST `/api/system/optimize/sysctl`
Apply sysctl optimization.

### POST `/api/system/optimize/all`
Run all optimization steps.

---

## Xray Utilities

### GET `/api/system/xray/version-current`
Get current xray versions.

### GET `/api/system/xray/versions`
List available xray versions.

### POST `/api/system/xray/switch`
Switch xray version.

### GET `/api/system/xray/reality-gen`
Generate Reality keypair/shortid.

### GET `/api/system/xray/config`
Get current xray config text.

### POST `/api/system/xray/config`
Save xray config text.

---

## Error Response (common)

```json
{ "success": false, "msg": "error message" }
```

HTTP status codes follow semantic meaning (`400/401/403/404/500`).
