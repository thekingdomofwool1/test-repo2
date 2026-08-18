/**
 * SAST BENCHMARK REPO #2: NODE.JS & EXPRESS VULNERABILITY TEST SUITE
 * WARNING: DO NOT DEPLOY TO PRODUCTION.
 * Designed to test SAST and AI-SAST differentiation across distinct JS/Node CWEs.
 */

const express = require('express');
const crypto = require('crypto');
const child_process = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');
const zlib = require('zlib');

const app = express();
app.use(express.json());

// ==========================================
# VULNERABILITY CLASS 1: HARDCODED SAAS & CLOUD TOKENS
// ==========================================

// [VULN: Stripe Live Secret Key] (CWE-798)
const STRIPE_SECRET_KEY = "sk_live_51M000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

// [VULN: Slack Bot Token] (CWE-798)
const SLACK_BOT_TOKEN = "xoxb-123456789012-1234567890123-a1b2c3d4e5f6g7h8i9j0k1l2";

// [VULN: Twilio API Key / Secret] (CWE-798)
const TWILIO_AUTH_TOKEN = "32980b12a81907c132890b12a81907c1";

// [VULN: RSA Private Key Literal] (CWE-798)
const JWT_PRIVATE_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIBOQIBAAJAd8J+r7B1...[EXEMPLAR_PRIVATE_KEY]...
-----END RSA PRIVATE KEY-----`;


// ==========================================
# VULNERABILITY CLASS 2: PROTOTYPE POLLUTION (CWE-1321)
// ==========================================

function recursiveMerge(target, source) {
    // [VULN: Prototype Pollution]
    // Missing check for '__proto__', 'constructor', or 'prototype' keys
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            recursiveMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

app.post('/api/settings/merge', (req, res) => {
    let userSettings = {};
    recursiveMerge(userSettings, req.body);
    // If req.body contains {"__proto__": {"isAdmin": true}}, global Object prototype is polluted!
    if (userSettings.isAdmin) {
        return res.send("Admin actions unlocked!");
    }
    res.send("Merged successfully.");
});


// ==========================================
# VULNERABILITY CLASS 3: REGULAR EXPRESSION DENIAL OF SERVICE (ReDoS) (CWE-400)
// ==========================================

app.post('/api/validate/email', (req, res) => {
    const { email } = req.body;
    // [VULN: ReDoS / Catastrophic Backtracking Regex]
    // Nested quantifiers ((a+)+$) cause exponential time complexity O(2^n) on payload like "aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
    const evilRegex = /^(([a-zA-Z0-9])+.)+[a-zA-Z0-9]+$/;
    
    if (evilRegex.test(email)) {
        return res.send("Valid email format");
    }
    return res.status(400).send("Invalid email");
});


// ==========================================
# VULNERABILITY CLASS 4: NoSQL INJECTION (CWE-943)
// ==========================================

// Mock MongoDB object
const mockMongoDb = {
    users: [
        { username: "admin", secret_note: "Top Secret Core Doc" },
        { username: "bob", secret_note: "Bob's Note" }
    ]
};

app.post('/api/nosql/login', (req, res) => {
    // [VULN: NoSQL Injection]
    // Express parses JSON query/body into objects. If req.body.username is {"$ne": null},
    // it bypasses string equality in MongoDB filter queries.
    const query = { username: req.body.username, password: req.body.password };
    
    // In actual Mongoose/MongoDB: db.collection('users').findOne(query)
    const found = mockMongoDb.users.find(u => 
        (typeof req.body.username === 'object' ? true : u.username === req.body.username)
    );

    if (found) {
        return res.json({ status: "Logged in", user: found });
    }
    return res.status(401).send("Auth failed");
});


// ==========================================
# VULNERABILITY CLASS 5: TIMING ATTACK ON HMAC SIGNATURES (CWE-208)
// ==========================================

app.post('/api/webhook/verify', (req, res) => {
    const signature = req.headers['x-signature'];
    const payload = JSON.stringify(req.body);
    
    const computedHash = crypto
        .createHmac('sha256', 'shared_webhook_secret')
        .update(payload)
        .digest('hex');

    // [VULN: Timing Attack / Insecure String Comparison]
    // Standard '===' short-circuits on first character mismatch, allowing byte-by-byte timing discovery
    // Should use crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(computedHash))
    if (signature === computedHash) {
        return res.send("Webhook verified");
    }
    res.status(403).send("Invalid signature");
});


// ==========================================
# VULNERABILITY CLASS 6: PERMISSIVE CORS & INSECURE COOKIES (CWE-942 / CWE-614)
// ==========================================

app.use('/api/sensitive', (req, res, next) => {
    // [VULN: Insecure CORS Policy] Wildcard Origin + Credentials enabled allows CSRF/data theft
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    next();
});

app.get('/api/sensitive/session', (req, res) => {
    // [VULN: Insecure Cookie Flags] Missing HttpOnly, Secure, and SameSite attributes
    res.cookie('auth_token', 'session_abc123', {
        httpOnly: false,
        secure: false,
        maxAge: 3600000
    });
    res.send({ status: "Session created" });
});


// ==========================================
# VULNERABILITY CLASS 7: ZIP SLIP / PATH TRAVERSAL DURING EXTRACTION (CWE-22)
// ==========================================

app.post('/api/extract-archive', (req, res) => {
    const entries = [
        { filename: "../../etc/cron.d/malicious_job", content: "echo 'hacked'" },
        { filename: "normal_file.txt", content: "hello" }
    ];

    const targetDir = path.join(__dirname, "uploads");

    entries.forEach(entry => {
        // [VULN: Zip Slip / Archive Extraction Path Traversal]
        // Doesn't verify if destination path starts with targetDir after resolution
        const destPath = path.resolve(targetDir, entry.filename);
        
        fs.writeFileSync(destPath, entry.content); // Can overwrite arbitrary files on system
    });

    res.send("Archive extracted");
});


// ==========================================
# VULNERABILITY CLASS 8: WEAK KEY DERIVATION / PBKDF2 (CWE-328 / CWE-916)
// ==========================================

function hashUserPassword(password) {
    const salt = "static_salt_123";
    // [VULN: Weak Key Derivation]
    // Iteration count = 1 (should be 600,000+), salt is static, algorithm SHA1 is deprecated
    return crypto.pbkdf2Sync(password, salt, 1, 64, 'sha1').toString('hex');
}


// ==========================================
# VULNERABILITY CLASS 9: SERVER-SIDE JS EVAL / FUNCTION INJECTION (CWE-94)
// ==========================================

app.get('/api/callback/timer', (req, res) => {
    const fnBody = req.query.onComplete || "console.log('Done')";
    
    // [VULN: Code Injection via Function Constructor / setTimeout string]
    // Passing a string to setTimeout or new Function executes arbitrary JS in Node process
    const customCallback = new Function(fnBody);
    setTimeout(customCallback, 100);

    res.send("Timer scheduled");
});


// ==========================================
# VULNERABILITY CLASS 10: UNVALIDATED REDIRECT WITH XSS / URI SCHEME (CWE-601 / CWE-79)
// ==========================================

app.get('/oauth/callback', (req, res) => {
    const returnUrl = req.query.return_to;
    // [VULN: Open Redirect + XSS]
    // Attacker can pass return_to=javascript:alert(document.cookie) or https://evil.com
    res.redirect(returnUrl);
});


// ==========================================
# VULNERABILITY CLASS 11: ASYNC RACE CONDITION / VOUCHER DOUBLE SPEND (CWE-362)
// ==========================================

const vouchers = {
    "PROMO100": { balance: 100, redeemedBy: [] }
};

app.post('/api/voucher/redeem', async (req, res) => {
    const { code, user } = req.body;
    const voucher = vouchers[code];

    if (!voucher || voucher.balance <= 0) {
        return res.status(400).send("Voucher invalid or empty");
    }

    // [VULN: Async Race Condition (TOCTOU)]
    // In Node event loop, awaiting I/O between balance check and balance decrement
    // allows concurrent requests from the same user to pass the balance > 0 check simultaneously.
    await new Promise(r => setTimeout(r, 50)); // Simulating DB latency

    voucher.balance -= 50;
    voucher.redeemedBy.push(user);

    res.send(`Redeemed! Remaining voucher balance: ${voucher.balance}`);
});


// ==========================================
# VULNERABILITY CLASS 12: INSECURE RANDOM NUMBER FOR OAUTH STATE (CWE-338)
// ==========================================

app.get('/oauth/start', (req, res) => {
    // [VULN: Insecure PRNG for CSRF / OAuth State Token]
    // Math.random() is non-cryptographic and predictable
    const stateToken = Math.random().toString(36).substring(2);
    res.redirect(`https://oauth.provider.com/auth?state=${stateToken}`);
});


// ==========================================
# VULNERABILITY CLASS 13: ACCOUNT ENUMERATION VIA TIMING DISCREPANCY (CWE-203)
// ==========================================

app.post('/api/auth/verify-user', (req, res) => {
    const { username, password } = req.body;
    const userDb = { "alice": "heavy_bcrypt_hash_simulated..." };

    if (!userDb[username]) {
        // [VULN: User Enumeration via Timing Discrepancy]
        // Immediate return takes ~1ms. If user exists, slow hashing takes ~100ms.
        // Attackers can enumerate valid usernames by measuring response latency.
        return res.status(401).send("Invalid user");
    }

    // Simulate heavy hash verification only when user exists
    crypto.pbkdf2Sync(password, "salt", 100000, 64, 'sha512');
    res.send("Verified");
});


app.listen(3000, () => {
    console.log("Vulnerable JS service listening on port 3000");
});
