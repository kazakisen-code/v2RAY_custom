# Minimal VLESS Worker

Cloudflare Pages/Workers မှာ run လုပ်နိုင်တဲ့ **VLESS-only** proxy worker။

## ✨ Features

- ⚡ VLESS protocol (WebSocket transport)
- 🔒 TLS support
- 🌐 DNS forwarding (UDP over TCP)
- 🎯 Custom ProxyIP support
- 🪶 Lightweight (~13KB)

## 🚀 Deploy

### 1. Fork this repo

### 2. Connect to Cloudflare Pages

[Cloudflare Dashboard](https://dash.cloudflare.com) → Pages → Create a project → Connect to GitHub

- **Build command:** (leave empty)
- **Build output directory:** `/`

### 3. Set Environment Variables

Pages → Settings → Functions → Environment variables:

| Variable | Required | Example | Description |
|----------|----------|---------|-------------|
| `UUID` | ✅ | `90cd4a77-141a-43c9-991b-08263cfe9c10` | Your VLESS UUID |
| `PROXYIP` | ❌ | `proxyip.example.com:443` | Custom proxy IP |
| `PATH` | ❌ | `/` | WebSocket path |

### 4. Get VLESS Link

```
vless://YOUR-UUID@your-domain.pages.dev:443?encryption=none&security=tls&type=ws&host=your-domain.pages.dev&path=/&fp=chrome&sni=your-domain.pages.dev#MyWorker
```

Replace:
- `YOUR-UUID` → your actual UUID
- `your-domain.pages.dev` → your Pages domain

## 🔧 Generate UUID

```bash
# Node.js
node -e "console.log(crypto.randomUUID())"

# Or use online tool: https://www.uuidgenerator.net/
```

## ⚠️ Notes

- Free tier: 100,000 requests/day
- Use **custom domain** for better TLS/SNI compatibility
- `PROXYIP` can improve speed (Cloudflare CDN IP recommended)

## 📜 License

GPL-2.0
