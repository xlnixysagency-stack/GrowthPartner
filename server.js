const http = require('http');
const crypto = require('crypto');

// These env vars are set in Render dashboard
const TURN_SECRET = process.env.TURN_SECRET || 'growthpartner_secret_change_me';
const PORT = process.env.PORT || 3000;

// Generate HMAC-SHA1 credentials for coturn / open-relay compatible TURN
function generateCredentials(uid) {
  const ttl = 24 * 3600; // 24 hours
  const timestamp = Math.floor(Date.now() / 1000) + ttl;
  const username = `${timestamp}:${uid || 'user'}`;
  const hmac = crypto.createHmac('sha1', TURN_SECRET);
  hmac.update(username);
  const credential = hmac.digest('base64');
  return { username, credential, ttl };
}

const server = http.createServer((req, res) => {
  // CORS — allow your Vercel/GitHub Pages domain
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }

  if (req.url.startsWith('/turn-credentials')) {
    const url = new URL(req.url, `http://localhost`);
    const uid = url.searchParams.get('uid') || 'user';
    const creds = generateCredentials(uid);

    // Return ICE server config ready to drop into RTCPeerConnection
    const iceServers = [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      // Open Relay TURN — works with HMAC credentials
      {
        urls: [
          'turn:openrelay.metered.ca:80',
          'turn:openrelay.metered.ca:443',
          'turn:openrelay.metered.ca:443?transport=tcp',
        ],
        username: creds.username,
        credential: creds.credential,
      },
      // Backup — hardcoded open relay fallback
      {
        urls: 'turn:openrelay.metered.ca:80',
        username: 'openrelayproject',
        credential: 'openrelayproject',
      },
    ];

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ iceServers, expiresAt: Date.now() + creds.ttl * 1000 }));
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`TURN credential server running on port ${PORT}`);
});