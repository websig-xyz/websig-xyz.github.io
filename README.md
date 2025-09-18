# WebSig Recovery Tool

Self-custody proof tool for WebSig wallet users. This tool allows users to recover their wallet using only their passkey, proving they have complete control of their keys.

## 🔐 Features

- **100% Client-Side**: No server requests, everything runs in your browser
- **Passkey Authentication**: Use your biometric to unlock your wallet
- **Multiple Accounts**: Derive multiple accounts (0, 1, 2, etc.) from your master seed
- **Secure Backups**: Create encrypted backups with a passphrase
- **No Dependencies**: Works standalone with just these two files

## 📦 Files

- `index.html` - The main recovery interface
- `recovery.js` - Client-side recovery logic
- `README.md` - This file

## 🚀 Deploy to GitHub Pages

### 1. Create a GitHub Repository

```bash
# Create new repo on GitHub (e.g., websig-recovery)
git init
git add index.html recovery.js README.md
git commit -m "Initial recovery tool"
git remote add origin https://github.com/YOUR_USERNAME/websig-recovery.git
git push -u origin main
```

### 2. Enable GitHub Pages

1. Go to Settings → Pages
2. Source: Deploy from branch
3. Branch: `main`, folder: `/ (root)`
4. Save

### 3. Custom Domain (Optional)

To use `recovery.websig.xyz`:

1. Create a `CNAME` file:
```bash
echo "recovery.websig.xyz" > CNAME
git add CNAME
git commit -m "Add custom domain"
git push
```

2. Configure DNS:
   - Add CNAME record: `recovery` → `YOUR_USERNAME.github.io`
   - Or use Cloudflare for SSL

### 4. Test

Your recovery tool will be available at:
- Default: `https://YOUR_USERNAME.github.io/websig-recovery/`
- Custom: `https://recovery.websig.xyz/`

## 🔒 Security

- **Content Security Policy**: Strict CSP prevents data exfiltration
- **No Inline Scripts**: All JavaScript in external files
- **HTTPS Only**: GitHub Pages enforces HTTPS
- **Domain Binding**: Passkeys are bound to `websig.xyz` domain

## ⚠️ Important Notes

1. **Domain Binding**: This tool only works for wallets created on `websig.xyz`
2. **Browser Support**: Requires a browser with WebAuthn and PRF extension support
3. **Backup Your Keys**: This is an emergency recovery tool, always keep secure backups

## 🧪 Local Testing

```bash
# Python 3
python3 -m http.server 8080

# Node.js
npx http-server -p 8080

# Then open http://localhost:8080
```

## 📝 License

Part of the WebSig wallet project. Use at your own risk.
