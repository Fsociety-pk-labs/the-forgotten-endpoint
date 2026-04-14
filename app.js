'use strict';
require('dotenv').config();

const express  = require('express');
const crypto   = require('crypto');
const path     = require('path');
const fs       = require('fs');

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────────
//  FLAGS  (never sent to frontend directly;
//          only returned after exploitation)
// ─────────────────────────────────────────────
const FLAGS = {
  f1: process.env.FLAG_1,
  f2: process.env.FLAG_2,
  f3: process.env.FLAG_3,
  f4: process.env.FLAG_4,
  f5: process.env.FLAG_5,
};

// ─────────────────────────────────────────────
//  WEAK JWT HELPERS
//  Secret is discoverable via the token itself.
//  This simulates tokens signed with a known /
//  guessable secret — a common real-world mistake.
// ─────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET;   // "fsociety"

function b64url(data) {
  return Buffer.from(JSON.stringify(data)).toString('base64url');
}

function makeToken(payload) {
  // Header exposes the key-id (kid) so a sharp analyst can guess the secret
  const header  = b64url({ alg: 'HS256', typ: 'JWT', kid: JWT_SECRET });
  const body    = b64url(payload);
  const sig     = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${header}.${body}`)
    .digest('base64url');
  return `${header}.${body}.${sig}`;
}

function parseToken(token) {
  try {
    const [h, b, s] = token.split('.');
    if (!h || !b || !s) return null;

    const payload = JSON.parse(Buffer.from(b, 'base64url').toString('utf8'));

    // Verify signature
    const expected = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${h}.${b}`)
      .digest('base64url');

    if (expected !== s) return null;
    return payload;
  } catch {
    return null;
  }
}

// ─────────────────────────────────────────────
//  STAGE 1 — robots.txt recon
//  Classic first step: check what the site hides
//  from search crawlers.
// ─────────────────────────────────────────────
app.get('/robots.txt', (_req, res) => {
  res.type('text/plain').send(
    `User-agent: *\n` +
    `Disallow: /s3cr3t-r00m\n` +
    `Disallow: /4dm1n\n` +
    `Disallow: /4p1/f1l3s\n`
  );
});

// Hidden room — returns Flag 1
app.get('/s3cr3t-r00m', (_req, res) => {
  res.json({
    status  : 'ACCESS GRANTED',
    message : 'You found the forgotten room. The first transmission is yours.',
    flag    : FLAGS.f1,
    flag_number: '1/5',
    flag_status: '🚩 FLAG 1/5 CAPTURED!',
    next    : 'Their login portal is weak. Social engineering? No — think SQL. Try /login',
  });
});

// ─────────────────────────────────────────────
//  STAGE 2 — SQL Injection bypass (educational)
//
//  CWE-89 / OWASP A03:
//  The server constructs a raw query string and
//  evaluates it as a boolean — simulating what
//  unsanitised SQL would do in production.
//
//  Payload:  username = ' OR '1'='1
//            password = anything
// ─────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username = '', password = '' } = req.body;

  // Simulated raw SQL:
  // SELECT * FROM agents WHERE username='<username>' AND password='<password>'
  //
  // When username is  ' OR '1'='1  the condition short-circuits to TRUE,
  // bypassing authentication entirely.
  const rawQuery =
    `SELECT * FROM agents WHERE username='${username}' AND password='${password}'`;

  // Evaluate whether the injected query would return rows
  const injected =
    /'\s*OR\s*'1'\s*=\s*'1/i.test(username) ||
    /'\s*OR\s*1\s*=\s*1/i.test(username)    ||
    /admin'\s*--/i.test(username)            ||
    /'\s*#/i.test(username);

  if (injected) {
    const token = makeToken({ user: 'agent_x', role: 'user', clearance: 1 });
    return res.json({
      status        : 'BYPASS SUCCESSFUL',
      query_executed: rawQuery,
      message       : 'Authentication gate destroyed. Welcome, unknown operative.',
      flag          : FLAGS.f2,
      flag_number   : '2/5',
      flag_status   : '🚩 FLAG 2/5 CAPTURED!',
      access_token  : token,
      directive     : 'Decode the token. Understand its structure. Then forge it.',
    });
  }

  // Valid credentials don't exist — only injection works
  res.status(401).json({
    status : 'DENIED',
    error  : 'Invalid credentials.',
    hint   : null,   // no hints in the API ;)
  });
});

// ─────────────────────────────────────────────
//  STAGE 3 — Weak JWT / Crypto forgery
//
//  The token from Stage 2 uses HS256 signed with
//  a trivially guessable secret embedded in the
//  JWT header's "kid" (Key ID) field.
//
//  Steps:
//   1. Base64url-decode part[0] → find "kid"
//   2. Base64url-decode part[1] → note role:"user"
//   3. Rebuild payload with   role:"moderator"
//   4. Re-sign with HMAC-SHA256 using the kid value
//   5. Send the forged token in Authorization header
// ─────────────────────────────────────────────
app.get('/api/profile', (req, res) => {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Bearer token required.' });
  }

  const payload = parseToken(auth.slice(7));

  if (!payload) {
    return res.status(403).json({ error: 'Token signature invalid. Forge more carefully.' });
  }

  if (payload.role === 'moderator') {
    // ROT13 hint → decoded: "the path isn't sanitized. try ../../secret/flag4.txt"
    return res.json({
      status      : 'ELEVATED ACCESS',
      user        : payload.user,
      flag        : FLAGS.f3,
      flag_number : '3/5',
      flag_status : '🚩 FLAG 3/5 CAPTURED!',
      transmission: 'The file API is running on a legacy Apache-style route.',
      // Encoded with ROT13 — decode it to find the next path
      encoded_msg : "gur cngu vfa'g fnavgvmrq. gel ../../frperg/synt4.gkg",
    });
  }

  // Token is valid but role is too low
  res.json({
    status : 'LIMITED ACCESS',
    user   : payload.user,
    role   : payload.role,
    message: 'Clearance insufficient. You need a higher role.',
  });
});

// ─────────────────────────────────────────────
//  STAGE 4 — Path Traversal  (CVE-2021-41773)
//
//  CVE-2021-41773: Apache HTTP Server 2.4.49
//  failed to properly neutralise path sequences
//  such as  /../  in URLs, allowing unauthenticated
//  attackers to read files outside the web root.
//
//  This endpoint replicates the same mistake:
//  the user-supplied `path` query parameter is
//  joined to a base directory WITHOUT validating
//  that the resolved path stays inside that dir.
//
//  Exploit: /4p1/f1l3s?path=../../secret/flag4.txt
//
//  Real fix: resolve the path, then assert it
//  starts with the intended base directory string.
// ─────────────────────────────────────────────
app.get('/4p1/f1l3s', (req, res) => {
  const { path: userPath } = req.query;

  if (!userPath) {
    return res.status(400).json({
      error : 'Missing ?path= parameter.',
      usage : '/4p1/f1l3s?path=readme.txt',
    });
  }

  // ⚠️  VULNERABLE: path.join does NOT prevent traversal.
  //     A safe implementation would use:
  //       const safe = path.resolve(base, userPath);
  //       if (!safe.startsWith(base)) return 403;
  const base       = path.join(__dirname, 'public', 'files');
  const targetPath = path.join(base, userPath);   // no guard — traversal possible!

  try {
    const content = fs.readFileSync(targetPath, 'utf8');
    res.json({ content });
  } catch {
    res.status(404).json({
      error: 'File not found.',
      tip  : 'Where might sensitive files live? Think outside the web root.',
    });
  }
});

// ─────────────────────────────────────────────
//  STAGE 5 — Admin panel
//
//  The JWT secret discovered in Stage 3 lets the
//  player forge a token with role:"admin" and
//  gain access to the final control panel.
// ─────────────────────────────────────────────
app.get('/4dm1n', (req, res) => {
  const auth = req.headers['authorization'] || '';
  if (!auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Admin credentials required.' });
  }

  const payload = parseToken(auth.slice(7));

  if (!payload) {
    return res.status(403).json({ error: 'Invalid token.' });
  }

  if (payload.role !== 'admin') {
    return res.status(403).json({
      error: 'Clearance level insufficient.',
      need : 'admin',
      have : payload.role,
    });
  }

  res.json({
    status             : '██ MISSION COMPLETE ██',
    flag               : FLAGS.f5,
    flag_number        : '5/5',
    flag_status        : '🚩 FLAG 5/5 CAPTURED!',
    final_transmission : 'The forgotten endpoint has fallen. The society never forgets.',
    agent              : payload.user,
  });
});

// ─────────────────────────────────────────────
//  404 catch-all
// ─────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: '404 — endpoint lost in the dark.' });
});

// ─────────────────────────────────────────────
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`\n  ███████╗███████╗ ██████╗  ██████╗██╗███████╗████████╗██╗   ██╗`);
  console.log(`  ██╔════╝██╔════╝██╔═══██╗██╔════╝██║██╔════╝╚══██╔══╝╚██╗ ██╔╝`);
  console.log(`  █████╗  ███████╗██║   ██║██║     ██║█████╗     ██║    ╚████╔╝ `);
  console.log(`  ██╔══╝  ╚════██║██║   ██║██║     ██║██╔══╝     ██║     ╚██╔╝  `);
  console.log(`  ██║     ███████║╚██████╔╝╚██████╗██║███████╗   ██║      ██║   `);
  console.log(`  ╚═╝     ╚══════╝ ╚═════╝  ╚═════╝╚═╝╚══════╝   ╚═╝      ╚═╝   `);
  console.log(`\n  CTF Challenge: The Forgotten Endpoint`);
  console.log(`  Running at   : http://localhost:${PORT}`);
  console.log(`  Good luck, agent.\n`);
});
