# WebSig Recovery Tool - Self-Custody Proof

[![Live Tool](https://img.shields.io/badge/Live-recovery.websig.xyz-green?style=for-the-badge)](https://recovery.websig.xyz)
[![Main App](https://img.shields.io/badge/Main_App-websig.xyz-blue?style=for-the-badge)](https://websig.xyz)

## Purpose

This tool proves WebSig users have **complete control** over their wallets. No company, backend, or third-party can access your funds - only you with your passkey.

## How to Verify Self-Custody

### Quick Test (2 minutes)
1. Create a wallet at [websig.xyz](https://websig.xyz)
2. Note your wallet address
3. Visit [recovery.websig.xyz](https://recovery.websig.xyz)
4. Click "Recover My Wallet" with the same passkey
5. **Result**: Same address appears = You have full control

### Technical Verification
```bash
# 1. Check network isolation (no backend calls)
curl -I https://recovery.websig.xyz
# Look for: Content-Security-Policy: connect-src 'none'

# 2. Verify source code
git clone https://github.com/websig-xyz/websig-xyz.github.io.git
cd websig-xyz.github.io

# 3. Confirm no network calls in code
grep -r "fetch\|XMLHttpRequest\|WebSocket" *.js *.html
# Result: No matches (except comments)

# 4. Check for external dependencies
grep -r "https://" index.html
# Only finds: Solana Web3.js CDN (for address formatting)
```

## Technology Stack

### Core Technologies Used

| Technology | Purpose | Why It Matters |
|------------|---------|----------------|
| **WebAuthn PRF** | Hardware-backed key derivation | Your passkey generates deterministic keys |
| **HMAC-SHA256** | Cryptographic PRF implementation | 256-bit entropy from your passkey |
| **HKDF-SHA256** | Key expansion | Derives account keys from master seed |
| **Ed25519** | Solana signatures | Industry-standard elliptic curve |
| **Web Crypto API** | Browser cryptography | Native, audited crypto implementations |

### Key Derivation Flow

```
Your Passkey (hardware-secured)
    ↓
WebAuthn PRF Extension
    ↓
HMAC-SHA256(passkey_private, "websig:solana:keypair:v1")
    ↓
256-bit Master Seed
    ↓
HKDF-SHA256(master_seed, "solana-bip44-path", "websig:account:v1")
    ↓
Ed25519 Keypair
    ↓
Your Solana Wallet
```

## Security Properties

### What This Tool Proves

✅ **Deterministic Derivation**: Same passkey always generates same wallet  
✅ **No Backend Dependency**: Works completely offline  
✅ **Open Source**: Every line of code is auditable  
✅ **No Hidden Keys**: No hardcoded seeds or backdoors  
✅ **Client-Side Only**: All crypto happens in your browser  

### How We Enforce Security

1. **Content Security Policy**
   ```html
   connect-src 'none'  <!-- Blocks ALL network requests -->
   ```

2. **No Private Key Storage**
   - Keys are derived on-demand
   - Never saved to disk
   - Cleared from memory after display

3. **Domain Binding**
   ```javascript
   rpId: 'websig.xyz'  // Passkeys bound to this domain
   ```
   - Prevents phishing (different domain = different keys)
   - Your passkey only works on websig.xyz domains

## Cryptographic Details

### PRF (Pseudo-Random Function) Extension

The WebAuthn PRF extension allows passkeys to derive deterministic secrets:

```javascript
// Simplified version of what happens
const credential = await navigator.credentials.get({
    publicKey: {
        rpId: 'websig.xyz',
        extensions: {
            prf: {
                eval: {
                    first: 'websig:solana:keypair:v1'  // Salt
                }
            }
        }
    }
})

// Result: 256 bits of deterministic entropy
const prfOutput = credential.extensions.prf.results.first
```

**Key Properties:**
- Same passkey + same salt = same output (always)
- Different domain = different output (phishing protection)
- Passkey private key never leaves hardware

### Account Derivation

Multiple accounts from one master seed:

```javascript
// BIP44-like derivation path
const accountSeed = HKDF(
    masterSeed,
    salt = `solana-bip44-m/44'/501'/${accountIndex}'/0'/0'`,
    info = 'websig:account:v1',
    length = 32
)
```

This ensures:
- Account 0, 1, 2... are all different
- Compromising one account doesn't affect others
- Standard derivation = compatible with recovery tool

## Frequently Asked Questions

### Can WebSig access my keys?
**No.** Keys are derived from your passkey in your browser. WebSig servers never see them.

### What if WebSig disappears?
You can always recover your wallet using this tool. It needs no backend.

### Can I verify the derivation myself?
Yes! The code is open source. Key functions to review:
- `deriveAccountSeed()` - BIP44 derivation
- `recoverWallet()` - PRF evaluation
- `hkdf()` - Key expansion

### Why not use a standard seed phrase?
Seed phrases can be:
- Lost or forgotten
- Stolen or phished  
- Compromised by malware

Passkeys are hardware-secured and can't be extracted.

### What browsers are supported?
Any browser with WebAuthn PRF support:
- Chrome/Edge 119+
- Safari 16.4+
- Brave (latest)
- Firefox (coming soon)

## For Security Researchers

### Audit Checklist

- [ ] Verify CSP header blocks network
- [ ] Confirm deterministic derivation
- [ ] Check for timing attacks in crypto
- [ ] Validate HKDF implementation
- [ ] Review PRF salt uniqueness
- [ ] Test cross-browser compatibility
- [ ] Verify memory cleanup

### Key Files to Review

```
recovery.js
├── Line 14-60: Cryptographic primitives
├── Line 86-104: Account derivation
├── Line 132-190: Wallet recovery flow
└── Line 262-296: Optional backup encryption
```

### Reporting Security Issues

Found a vulnerability? Please report responsibly:
- Email: security@websig.xyz

## Build & Deploy

### Local Testing
```bash
# Clone repository
git clone https://github.com/websig-xyz/websig-xyz.github.io.git
cd websig-xyz.github.io

# Serve locally (any static server)
python3 -m http.server 8080

# Visit http://localhost:8080
```

### Files
- `index.html` - User interface
- `recovery.js` - Cryptographic logic
- `CNAME` - Custom domain configuration

### GitHub Pages Deployment
This tool is automatically deployed via GitHub Pages when pushed to the main branch.

## License

MIT License - Open source for transparency and trust.

---

**Bottom Line**: This tool proves you don't need to trust WebSig. Your passkey IS your wallet. We can't access it, freeze it, or steal it. This is true self-custody.

Verify it yourself: [recovery.websig.xyz](https://recovery.websig.xyz) 🔐