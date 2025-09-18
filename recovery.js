/**
 * WebSig Recovery Tool - Cryptographic Self-Custody Proof
 * 
 * This tool proves you have complete control over your wallet by deriving
 * your Solana private key directly from your passkey using standard cryptography:
 * - WebAuthn PRF Extension: Hardware-backed key derivation
 * - HKDF-SHA256: Cryptographically secure key expansion
 * - BIP44-like paths: Deterministic account derivation
 * 
 * Security: Runs 100% client-side, CSP blocks all network requests
 * Verification: Open source at github.com/websig-xyz/websig-xyz.github.io
 */

const BUILD_VERSION = 'v1.0.4-20250117-technical';

// Global state
let currentKeypair = null;
let currentMasterSeed = null; // 256-bit entropy from PRF
let isKeyRevealed = false;

/**
 * Cryptographic Primitives using Web Crypto API
 * All operations use NIST-approved algorithms
 */
async function sha256(data) {
    const encoded = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
    return new Uint8Array(hashBuffer);
}

/**
 * HKDF-SHA256 (NIST SP 800-56C Rev. 2)
 * Cryptographically secure key derivation function
 * @param {Uint8Array} secret - Input key material (IKM)
 * @param {Uint8Array} salt - Salt for domain separation
 * @param {Uint8Array} info - Context/version binding
 * @param {number} length - Output length in bytes
 * @returns {Uint8Array} Derived key material
 */
async function hkdf(secret, salt, info, length = 32) {
    const key = await crypto.subtle.importKey(
        'raw',
        secret,
        { name: 'HKDF' },
        false,
        ['deriveBits']
    );
    
    const bits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: salt,
            info: info
        },
        key,
        length * 8
    );
    
    return new Uint8Array(bits);
}

function base64urlEncode(bytes) {
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64urlDecode(b64u){
    const b64 = b64u.replace(/-/g,'+').replace(/_/g,'/') + '=='.slice((2 - (b64u.length * 3) % 4) % 4);
    const raw = atob(b64);
    const out = new Uint8Array(raw.length);
    for (let i=0;i<raw.length;i++) out[i] = raw.charCodeAt(i);
    return out;
}

async function aesGcmDecrypt(keyBytes, ciphertextB64u, ivB64u, aad){
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    const dec = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: base64urlDecode(ivB64u), additionalData: aad ? new TextEncoder().encode(aad) : undefined },
        key,
        base64urlDecode(ciphertextB64u)
    );
    return new Uint8Array(dec);
}

/**
 * BIP44-inspired deterministic account derivation
 * Uses HKDF for cryptographic key separation between accounts
 * 
 * Derivation path: m/44'/501'/${accountIndex}'/0'/0'
 * - 44': BIP44 standard
 * - 501': Solana coin type
 * - accountIndex': User account (hardened)
 * 
 * @param {Uint8Array} masterSeed - 256-bit master seed from PRF
 * @param {number} accountIndex - Account index (0-based)
 * @returns {Uint8Array} 256-bit account-specific seed for Ed25519
 */
async function deriveAccountSeed(masterSeed, accountIndex){
    const path = `m/44'/501'/${accountIndex}'/0'/0'`;
    const salt = new TextEncoder().encode(`solana-bip44-${path}`);
    const info = new TextEncoder().encode('websig:account:v1');
    return await hkdf(masterSeed, salt, info, 32);
}


async function updateDerivedAccount(){
    if (!currentMasterSeed) return;
    
    // Check if Solana library is loaded
    if (!window.solanaWeb3 || !window.solanaWeb3.Keypair) {
        console.error('Solana Web3.js not loaded yet');
        return;
    }
    
    const idx = Math.max(0, parseInt(document.getElementById('accountIndex').value || '0', 10));
    const acctSeed = await deriveAccountSeed(currentMasterSeed, idx);
    currentKeypair = window.solanaWeb3.Keypair.fromSeed(acctSeed);
    document.getElementById('address').textContent = currentKeypair.publicKey.toBase58();
    document.getElementById('privateKey').textContent = '[' + currentKeypair.secretKey.toString() + ']';
    document.getElementById('privateKeyB58').textContent = base58Encode(currentKeypair.secretKey);
}

function activateStep(stepNumber) {
    document.querySelectorAll('.step').forEach(step => {
        step.classList.remove('active');
    });
    document.getElementById(`step${stepNumber}`).classList.add('active');
}

async function recoverWallet() {
    const btn = document.getElementById('recoverBtn');
    btn.disabled = true;
    btn.innerHTML = '🔄 Authenticating...';
    
    try {
        // Step 1: Authenticate with passkey
        activateStep(1);
        
        // Check if WebAuthn is supported
        if (!window.PublicKeyCredential) {
            throw new Error('WebAuthn not supported in this browser');
        }
        
        // Create a challenge
        const challenge = crypto.getRandomValues(new Uint8Array(32));
        
        /**
         * WebAuthn PRF Extension (Level 3 Specification)
         * Evaluates HMAC-SHA256(credential_private_key, salt)
         * The credential private key never leaves the hardware security module
         */
        const credential = await navigator.credentials.get({
            publicKey: {
                challenge: challenge,
                rpId: 'websig.xyz', // Domain binding - prevents phishing
                userVerification: 'required', // Biometric/PIN mandatory
                extensions: {
                    prf: {
                        eval: {
                            // Salt for PRF - deterministic wallet derivation
                            first: new TextEncoder().encode('websig:solana:keypair:v1')
                        }
                    }
                }
            }
        });
        
        // Verify PRF was evaluated successfully
        if (!credential.getClientExtensionResults().prf?.results?.first) {
            throw new Error('PRF extension not supported or no result');
        }
        
        // Step 2: Derive wallet
        activateStep(2);
        btn.innerHTML = '🔄 Deriving wallet...';
        
        // Extract PRF output (256 bits of entropy)
        const prfOutput = credential.getClientExtensionResults().prf.results.first;
        const prfBytes = new Uint8Array(prfOutput);

        // Compute credential ID hash for wrap decryption
        const rawId = new Uint8Array(credential.rawId);
        const credHash = await sha256(rawId);

        // Master seed: First 32 bytes of PRF output (256-bit security)
        let masterSeed = prfBytes.slice(0, 32);

        // Optional: Cross-ecosystem wrap decryption
        const wrapText = (document.getElementById('wrapInput').value || '').trim();
        if (wrapText) {
            try {
                const wrap = JSON.parse(wrapText);
                const rpId = wrap.rpId || 'websig.xyz';
                // Derive wrap key: sha256(prf || credHash || rpId)
                const rpIdBytes = new TextEncoder().encode(rpId);
                const combined = new Uint8Array(prfBytes.length + credHash.length + rpIdBytes.length);
                combined.set(prfBytes, 0);
                combined.set(credHash, prfBytes.length);
                combined.set(rpIdBytes, prfBytes.length + credHash.length);
                const wrapKey = await sha256(combined);
                const aad = `${rpId}|v1`;
                const decrypted = await aesGcmDecrypt(wrapKey, wrap.ciphertext, wrap.iv, aad);
                masterSeed = decrypted.slice(0, 32);
            } catch (e) {
                console.warn('Failed to use provided wrap, falling back to PRF-only seed:', e);
            }
        }

        // Store master seed and derive initial account
        currentMasterSeed = masterSeed;
        await updateDerivedAccount();
        
        // Step 3: Display recovered wallet
        activateStep(3);
        btn.innerHTML = '✅ Wallet Recovered!';
        document.getElementById('walletInfo').classList.add('active');
        
    } catch (error) {
        console.error('Recovery failed:', error);
        alert(`Recovery failed: ${error.message}\n\nMake sure you're using the same domain where you created your wallet.`);
        btn.disabled = false;
        btn.innerHTML = '🔓 Recover My Wallet';
    }
}

function revealPrivateKey() {
    const privateKeyEl = document.getElementById('privateKey');
    const btn = document.getElementById('revealBtn');
    
    if (isKeyRevealed) {
        privateKeyEl.classList.add('hidden');
        btn.innerHTML = '👁 Reveal Private Key';
        isKeyRevealed = false;
    } else {
        if (confirm('⚠️ WARNING: Make sure no one is looking at your screen. Reveal private key?')) {
            privateKeyEl.classList.remove('hidden');
            btn.innerHTML = '🙈 Hide Private Key';
            isKeyRevealed = true;
        }
    }
}

function copyPrivateKey() {
    if (!currentKeypair) return;
    
    const keyString = '[' + currentKeypair.secretKey.toString() + ']';
    navigator.clipboard.writeText(keyString);
    alert('✅ Private key copied to clipboard');
}

// Minimal Base58 encoder
const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Encode(input) {
    if (!input || input.length === 0) return '';
    const bytes = Array.from(input);
    let encoded = '';
    while (bytes.some(b => b !== 0)) {
        let carry = 0;
        for (let i = 0; i < bytes.length; i++) {
            carry = carry * 256 + bytes[i];
            bytes[i] = Math.floor(carry / 58);
            carry = carry % 58;
        }
        encoded = ALPHABET[carry] + encoded;
    }
    for (let i = 0; i < input.length && input[i] === 0; i++) {
        encoded = '1' + encoded;
    }
    return encoded;
}

function copyPrivateKeyB58(){
    if (!currentKeypair) return;
    const b58 = base58Encode(currentKeypair.secretKey);
    navigator.clipboard.writeText(b58);
    alert('✅ Base58 private key copied');
}

function stepAccount(delta){
    const input = document.getElementById('accountIndex');
    let val = parseInt(input.value || '0', 10);
    val = Math.max(0, val + delta);
    input.value = String(val);
    updateDerivedAccount();
}

async function downloadBackup() {
    if (!currentKeypair || !currentMasterSeed) return;

    // Create an encrypted backup of the master seed using a user-supplied passphrase
    const passphrase = prompt('Enter a passphrase to encrypt your backup (store safely!)');
    if (!passphrase) return;

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const info = new TextEncoder().encode('websig:backup:v1');
    const key = await hkdf(new TextEncoder().encode(passphrase), salt, info, 32);

    const ivArr = crypto.getRandomValues(new Uint8Array(12));
    const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
    const enc = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: ivArr }, cryptoKey, currentMasterSeed);

    const backup = {
        type: 'websig-wallet-backup',
        version: '2.0',
        timestamp: new Date().toISOString(),
        address: currentKeypair.publicKey.toBase58(),
        encryptedSeed: base64urlEncode(new Uint8Array(enc)),
        iv: base64urlEncode(ivArr),
        salt: base64urlEncode(salt),
        kdf: 'HKDF-SHA256',
        info: 'websig:backup:v1',
        warning: 'Store this file and your passphrase securely. Both are required to restore.'
    };

    const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `websig-backup-${currentKeypair.publicKey.toBase58().slice(0, 8)}.json`;
    a.click();
}

function generateQR() {
    alert('QR code generation would require a QR library. For now, use the Copy Key feature.');
}

// Wait for Solana Web3.js to load
function waitForSolana(callback) {
    let attempts = 0;
    const maxAttempts = 50; // 5 seconds max wait
    
    const checkInterval = setInterval(() => {
        attempts++;
        
        // Check for Solana library
        if (window.solanaWeb3 && window.solanaWeb3.Keypair) {
            clearInterval(checkInterval);
            console.log('✅ Solana Web3.js loaded successfully');
            callback();
        } else if (attempts >= maxAttempts) {
            clearInterval(checkInterval);
            console.error('❌ Failed to load Solana Web3.js after 5 seconds');
            alert('Failed to load Solana library. Please refresh the page and try again.');
        }
    }, 100); // Check every 100ms
}

// Show domain info and wire up event handlers
window.addEventListener('DOMContentLoaded', () => {
    console.log(`WebSig Recovery Tool ${BUILD_VERSION}`);
    console.log('Domain:', window.location.hostname);
    console.log('🔒 100% OFFLINE - No backend connections allowed by CSP');
    console.log('📝 Derivation matches main app: PRF → Master Seed → BIP44 → Account');
    
    // Wait for Solana to load before setting up handlers
    waitForSolana(() => {
        console.log('Solana library ready, setting up event handlers...');
        
        // Wire up all event handlers
        const recoverBtn = document.getElementById('recoverBtn');
        if (recoverBtn) {
            recoverBtn.addEventListener('click', recoverWallet);
        }
        
        const revealBtn = document.getElementById('revealBtn');
        if (revealBtn) {
            revealBtn.addEventListener('click', revealPrivateKey);
        }
        
        const copyKeyBtn = document.getElementById('copyKeyBtn');
        if (copyKeyBtn) {
            copyKeyBtn.addEventListener('click', copyPrivateKey);
        }
        
        const copyB58Btn = document.getElementById('copyB58Btn');
        if (copyB58Btn) {
            copyB58Btn.addEventListener('click', copyPrivateKeyB58);
        }
        
        const downloadBackupBtn = document.getElementById('downloadBackupBtn');
        if (downloadBackupBtn) {
            downloadBackupBtn.addEventListener('click', downloadBackup);
        }
        
        const qrBtn = document.getElementById('qrBtn');
        if (qrBtn) {
            qrBtn.addEventListener('click', generateQR);
        }
        
        // Account index navigation
        const decBtn = document.getElementById('decIdx');
        if (decBtn) {
            decBtn.addEventListener('click', () => stepAccount(-1));
        }
        
        const incBtn = document.getElementById('incIdx');
        if (incBtn) {
            incBtn.addEventListener('click', () => stepAccount(1));
        }
        
        const accountInput = document.getElementById('accountIndex');
        if (accountInput) {
            accountInput.addEventListener('change', updateDerivedAccount);
        }
    });
});
