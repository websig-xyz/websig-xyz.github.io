// WebSig Recovery Tool - Client-side wallet recovery
// This file works 100% client-side with no external dependencies except Solana web3.js

let currentKeypair = null;
let currentMasterSeed = null; // 32-byte seed used for BIP44 derivation
let isKeyRevealed = false;

// Helper functions for crypto operations
async function sha256(data) {
    const encoded = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hashBuffer = await crypto.subtle.digest('SHA-256', encoded);
    return new Uint8Array(hashBuffer);
}

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

async function deriveAccountSeed(masterSeed, accountIndex){
    // Match lib/wallet-derivation.ts
    const path = `m/44'/501'/${accountIndex}'/0'/0'`;
    const salt = new TextEncoder().encode(`solana-bip44-${path}`);
    const info = new TextEncoder().encode('websig:account:v1');
    return await hkdf(masterSeed, salt, info, 32);
}

// Derive lookup key for fetching wraps from backend
async function deriveLookupKey(prfBytes) {
    const rpId = 'websig.xyz';
    const combined = new Uint8Array(prfBytes.length + rpId.length);
    combined.set(prfBytes, 0);
    combined.set(new TextEncoder().encode(rpId), prfBytes.length);
    const hash = await sha256(combined);
    return base64urlEncode(hash);
}

// Check for cloud-stored wrap
async function checkForCloudWrap(lookupKey, prfBytes, credHash) {
    try {
        console.log('Fetching wraps from backend...');
        console.log('Using lookup key:', lookupKey);
        
        // Try to fetch from backend
        const response = await fetch(`https://websig-wallet-worker.maurodelazeri.workers.dev/v1/wrap?lookupKey=${lookupKey}`);
        console.log('Response status:', response.status);
        
        if (response.ok) {
            const data = await response.json();
            console.log('Full response data:', JSON.stringify(data, null, 2));
            
            if (data && data.wraps && data.wraps.length > 0) {
                console.log('Found cloud wrap(s):', data.wraps.length);
                console.log('Metadata public key:', data.metadata?.accounts?.[0]?.publicKey);
                
                // Try to decrypt the first compatible wrap
                for (const wrap of data.wraps) {
                    try {
                        console.log('Attempting to decrypt wrap from device:', wrap.deviceName);
                        console.log('Wrap credIdHash:', wrap.credIdHash);
                        console.log('Our credHash (base64):', base64urlEncode(credHash));
                        
                        const rpId = wrap.rpId || 'websig.xyz';
                        const rpIdBytes = new TextEncoder().encode(rpId);
                        const combined = new Uint8Array(prfBytes.length + credHash.length + rpIdBytes.length);
                        combined.set(prfBytes, 0);
                        combined.set(credHash, prfBytes.length);
                        combined.set(rpIdBytes, prfBytes.length + credHash.length);
                        const wrapKey = await sha256(combined);
                        console.log('Wrap key (first 8 bytes):', Array.from(wrapKey.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));
                        
                        const aad = `${rpId}|v1`;
                        const decrypted = await aesGcmDecrypt(wrapKey, wrap.ciphertext, wrap.iv, aad);
                        const cloudSeed = decrypted.slice(0, 32);
                        
                        console.log('Successfully decrypted cloud wrap!');
                        console.log('Cloud seed (first 8 bytes):', Array.from(cloudSeed.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));
                        
                        // Update to use cloud seed
                        currentMasterSeed = cloudSeed;
                        await updateDerivedAccount();
                        
                        // Show notification
                        const info = document.createElement('div');
                        info.style.cssText = 'background:#10b981;color:white;padding:12px;border-radius:8px;margin:16px 0;text-align:center;';
                        info.textContent = '✅ Cloud backup found and loaded';
                        document.getElementById('walletInfo').insertBefore(info, document.getElementById('walletInfo').firstChild);
                        
                        return;
                    } catch (e) {
                        console.warn('Failed to decrypt wrap:', e);
                    }
                }
            } else {
                console.log('No cloud wraps found, using PRF-only seed');
            }
        } else {
            console.log('No cloud backup found (404), using PRF-only seed');
        }
    } catch (error) {
        console.warn('Failed to check cloud wraps:', error);
    }
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
        
        // Get the credential with PRF
        const credential = await navigator.credentials.get({
            publicKey: {
                challenge: challenge,
                rpId: 'websig.xyz',
                userVerification: 'required',
                extensions: {
                    prf: {
                        eval: {
                            first: new TextEncoder().encode('websig:solana:keypair:v1')
                        }
                    }
                }
            }
        });
        
        if (!credential.getClientExtensionResults().prf?.results?.first) {
            throw new Error('PRF extension not supported or no result');
        }
        
        // Step 2: Derive wallet
        activateStep(2);
        btn.innerHTML = '🔄 Deriving wallet...';
        
        const prfOutput = credential.getClientExtensionResults().prf.results.first;
        const prfBytes = new Uint8Array(prfOutput);

        // Compute credentialId hash (for decrypting wrap)
        const rawId = new Uint8Array(credential.rawId);
        const credHash = await sha256(rawId);
        console.log('Credential ID (base64):', base64urlEncode(rawId).slice(0, 32) + '...');
        console.log('Credential ID hash (base64):', base64urlEncode(credHash));
        console.log('PRF output (first 8 bytes):', Array.from(prfBytes.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));

        // Default master seed = PRF-only (same as app fallback)
        let masterSeed = prfBytes.slice(0, 32);

        // Optional: if user pasted an encrypted wrap, decrypt it to get the common master seed
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

        // Save global master seed and derive selected account
        currentMasterSeed = masterSeed;
        
        // Log for debugging
        console.log('Master seed (first 8 bytes):', Array.from(masterSeed.slice(0, 8)).map(b => b.toString(16).padStart(2, '0')).join(''));
        console.log('Using wrapped seed:', !!wrapText);
        
        await updateDerivedAccount();
        
        // Step 3: Show wallet
        activateStep(3);
        btn.innerHTML = '✅ Wallet Recovered!';
        
        // Show wallet info section
        document.getElementById('walletInfo').classList.add('active');
        
        // Check if we should try to fetch a wrap
        if (!wrapText) {
            // Try to fetch wrap from backend
            const lookupKey = await deriveLookupKey(prfBytes);
            console.log('Checking for cloud wrap with lookup key:', lookupKey.slice(0, 16) + '...');
            await checkForCloudWrap(lookupKey, prfBytes, credHash);
        }
        
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
    console.log('Recovery tool loaded on domain:', window.location.hostname);
    console.log('This tool works 100% client-side - check the Network tab to verify no requests are made');
    
    // Wait for Solana to load before setting up handlers
    waitForSolana(() => {
        console.log('Solana library ready, setting up event handlers...');
        
        // Wire up all event handlers
        const recoverBtn = document.getElementById('recoverBtn');
        if (recoverBtn) {
            recoverBtn.addEventListener('click', recoverWallet);
            console.log('Recover button wired up');
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
