// ========== MINIMAL VLESS WORKER ==========
// Based on cmliu/edgetunnel - stripped down to VLESS-only core
// Version: 2026-06-27

const CONFIG = {
  UUID: 'YOUR-UUID-HERE',        // Change this to your UUID
  PROXYIP: '',                    // Optional: custom proxy IP
  PATH: '/',                      // WebSocket path
  LOG: false                      // Enable debug logging
};

// ========== VLESS PROTOCOL CONSTANTS ==========
const WS_EARLY_DATA_MAX_BYTES = 8192;
const WS_EARLY_DATA_MAX_HEADER_LENGTH = Math.ceil(WS_EARLY_DATA_MAX_BYTES * 4 / 3) + 4;

// ========== MAIN ENTRY ==========
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();

    const userID = env.UUID || CONFIG.UUID;
    const proxyIP = env.PROXYIP || CONFIG.PROXYIP;
    const wsPath = env.PATH || CONFIG.PATH;

    // Check path match (optional security)
    if (wsPath !== '/' && url.pathname !== wsPath) {
      return new Response('Not Found', { status: 404 });
    }

    // WebSocket upgrade for VLESS
    if (upgradeHeader === 'websocket') {
      return await handleVLESS(request, userID, proxyIP, url);
    }

    // Simple status page
    if (url.pathname === '/status') {
      return new Response(JSON.stringify({ 
        status: 'ok', 
        protocol: 'vless',
        transport: 'websocket',
        uuid: userID.slice(0, 8) + '****' + userID.slice(-4)
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    return new Response('Not Found', { status: 404 });
  }
};

// ========== WEBSOCKET VLESS HANDLER ==========
async function handleVLESS(request, userID, proxyIP, url) {
  const wsPair = new WebSocketPair();
  const [clientSocket, serverSocket] = Object.values(wsPair);

  try {
    serverSocket.accept({ allowHalfOpen: true });
  } catch (_) {
    serverSocket.accept();
  }

  serverSocket.binaryType = 'arraybuffer';

  let remoteSocket = null;
  let isDnsQuery = false;
  let protocolType = null;

  // Get TCP connector from request (CF Workers specific)
  const tcpConnector = createTCPConnector(request);

  // Handle early data from sec-websocket-protocol header
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

  // Message handler
  serverSocket.addEventListener('message', async (event) => {
    try {
      const data = new Uint8Array(event.data);

      // If remote connection exists, forward data
      if (remoteSocket) {
        const writer = remoteSocket.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return;
      }

      // First message: parse protocol
      if (protocolType === null) {
        // Check for Trojan (56 bytes hash + \r\n)
        if (data.length >= 58 && data[56] === 0x0d && data[57] === 0x0a) {
          serverSocket.close();
          return; // Trojan not supported in minimal version
        }

        // Parse VLESS
        protocolType = 'vless';
        const result = parseVLESS(data, userID);

        if (result.hasError) {
          log('VLESS parse error:', result.message);
          serverSocket.close();
          return;
        }

        const { version, hostname, port, isUDP, rawClientData } = result;

        // Block speedtest sites
        if (isSpeedTestSite(hostname)) {
          serverSocket.close();
          return;
        }

        // Handle UDP (DNS only on port 53)
        if (isUDP) {
          if (port !== 53) {
            serverSocket.close();
            return;
          }
          isDnsQuery = true;
          await forwardDNS(rawClientData, serverSocket, version, tcpConnector);
          return;
        }

        // Connect to target
        try {
          const targetHost = proxyIP ? proxyIP.split(':')[0] : hostname;
          const targetPort = proxyIP 
            ? (proxyIP.includes(':') ? parseInt(proxyIP.split(':')[1]) : 443)
            : port;

          remoteSocket = await connectTCP(tcpConnector, targetHost, targetPort, rawClientData);

          // Send VLESS response header [version, 0]
          const respHeader = new Uint8Array([version, 0]);
          serverSocket.send(respHeader);

          // Start piping remote -> WebSocket
          pipeRemoteToWS(remoteSocket, serverSocket);

        } catch (err) {
          log('Connection failed:', err.message);
          serverSocket.close();
        }

      } else {
        // Forward subsequent messages
        if (remoteSocket) {
          const writer = remoteSocket.writable.getWriter();
          await writer.write(data);
          writer.releaseLock();
        }
      }

    } catch (err) {
      log('WS message error:', err.message);
      serverSocket.close();
    }
  });

  serverSocket.addEventListener('close', () => {
    if (remoteSocket) {
      try { remoteSocket.close(); } catch (e) {}
    }
  });

  serverSocket.addEventListener('error', (err) => {
    log('WS error:', err);
    if (remoteSocket) {
      try { remoteSocket.close(); } catch (e) {}
    }
  });

  // Handle early data
  if (earlyDataHeader) {
    try {
      const bytes = decodeEarlyData(earlyDataHeader, userID);
      if (bytes && bytes.byteLength) {
        // Re-dispatch as message event
        setTimeout(() => {
          if (serverSocket.readyState === WebSocket.OPEN) {
            serverSocket.dispatchEvent(new MessageEvent('message', { data: bytes.buffer }));
          }
        }, 0);
      }
    } catch (e) {
      log('Early data error:', e.message);
    }
  }

  return new Response(null, { 
    status: 101, 
    webSocket: clientSocket,
    headers: { 'Sec-WebSocket-Extensions': '' }
  });
}

// ========== VLESS REQUEST PARSER ==========
function parseVLESS(data, userID) {
  const length = data.byteLength;

  if (length < 24) {
    return { hasError: true, message: 'Data too short' };
  }

  const version = data[0];

  // Check UUID (16 bytes at offset 1)
  if (!uuidBytesMatch(data, 1, userID)) {
    return { hasError: true, message: 'Invalid UUID' };
  }

  const optLen = data[17];
  const cmdIndex = 18 + optLen;

  if (length < cmdIndex + 4) {
    return { hasError: true, message: 'Invalid command position' };
  }

  const cmd = data[cmdIndex];
  let isUDP = false;

  if (cmd === 1) {
    // TCP
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return { hasError: true, message: 'Unsupported command: ' + cmd };
  }

  const portIdx = cmdIndex + 1;
  const port = (data[portIdx] << 8) | data[portIdx + 1];

  let addrIdx = portIdx + 3;
  let addrLen = 0;
  let hostname = '';

  const addressType = data[portIdx + 2];

  switch (addressType) {
    case 1: // IPv4
      addrLen = 4;
      if (length < addrIdx + addrLen) {
        return { hasError: true, message: 'IPv4 address too short' };
      }
      hostname = `${data[addrIdx]}.${data[addrIdx+1]}.${data[addrIdx+2]}.${data[addrIdx+3]}`;
      break;

    case 2: // Domain
      if (length < addrIdx + 1) {
        return { hasError: true, message: 'Domain length missing' };
      }
      addrLen = data[addrIdx];
      addrIdx++;
      if (length < addrIdx + addrLen) {
        return { hasError: true, message: 'Domain data too short' };
      }
      hostname = new TextDecoder().decode(data.subarray(addrIdx, addrIdx + addrLen));
      break;

    case 3: // IPv6
      addrLen = 16;
      if (length < addrIdx + addrLen) {
        return { hasError: true, message: 'IPv6 address too short' };
      }
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        const base = addrIdx + i * 2;
        ipv6.push(((data[base] << 8) | data[base + 1]).toString(16));
      }
      hostname = ipv6.join(':');
      break;

    default:
      return { hasError: true, message: 'Unknown address type: ' + addressType };
  }

  if (!hostname) {
    return { hasError: true, message: 'Empty hostname' };
  }

  const rawIndex = addrIdx + addrLen;

  return {
    hasError: false,
    version,
    addressType,
    port,
    hostname,
    isUDP,
    rawClientData: data.subarray(rawIndex)
  };
}

// ========== UUID UTILITIES ==========
const uuidBytesCache = new Map();

function getUUIDBytes(uuid) {
  let cached = uuidBytesCache.get(uuid);
  if (cached) return cached;

  const clean = uuid.replace(/-/g, '').toLowerCase();
  if (clean.length !== 32) return null;

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    const high = parseInt(clean[i * 2], 16);
    const low = parseInt(clean[i * 2 + 1], 16);
    if (isNaN(high) || isNaN(low)) return null;
    bytes[i] = (high << 4) | low;
  }

  if (uuidBytesCache.size >= 32) uuidBytesCache.clear();
  uuidBytesCache.set(uuid, bytes);
  return bytes;
}

function uuidBytesMatch(data, offset, uuid) {
  const expected = getUUIDBytes(uuid);
  if (!expected || data.byteLength < offset + 16) return false;
  for (let i = 0; i < 16; i++) {
    if (data[offset + i] !== expected[i]) return false;
  }
  return true;
}

// ========== TCP CONNECTION ==========
function createTCPConnector(request) {
  const req = request;
  if (!req.fetcher || typeof req.fetcher.connect !== 'function') {
    throw new Error('request.fetcher.connect unavailable - not running in Cloudflare Workers');
  }
  return (options) => req.fetcher.connect(options);
}

async function connectTCP(connector, hostname, port, initialData) {
  const socket = connector({ hostname, port });
  await socket.opened;

  if (initialData && initialData.byteLength > 0) {
    const writer = socket.writable.getWriter();
    await writer.write(initialData);
    writer.releaseLock();
  }

  return socket;
}

function pipeRemoteToWS(remoteSocket, wsSocket) {
  const reader = remoteSocket.readable.getReader();

  (async () => {
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value || value.byteLength === 0) continue;

        if (wsSocket.readyState === WebSocket.OPEN) {
          wsSocket.send(value);
        } else {
          break;
        }
      }
    } catch (err) {
      log('Remote read error:', err.message);
    } finally {
      try { reader.releaseLock(); } catch (e) {}
      try { wsSocket.close(); } catch (e) {}
    }
  })();

  wsSocket.addEventListener('close', () => {
    try { reader.cancel(); } catch (e) {}
    try { remoteSocket.close(); } catch (e) {}
  });
}

// ========== DNS FORWARDING (UDP over TCP) ==========
async function forwardDNS(dnsData, wsSocket, version, tcpConnector) {
  try {
    const tcpSocket = tcpConnector({ hostname: '8.8.4.4', port: 53 });
    await tcpSocket.opened;

    const writer = tcpSocket.writable.getWriter();
    await writer.write(dnsData);
    writer.releaseLock();

    // Send VLESS response header
    const respHeader = new Uint8Array([version, 0]);
    wsSocket.send(respHeader);

    const reader = tcpSocket.readable.getReader();

    (async () => {
      try {
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (wsSocket.readyState === WebSocket.OPEN) {
            wsSocket.send(value);
          }
        }
      } catch (e) {
        log('DNS read error:', e.message);
      } finally {
        try { reader.releaseLock(); } catch (e) {}
      }
    })();

  } catch (err) {
    log('DNS forward error:', err.message);
    wsSocket.close();
  }
}

// ========== EARLY DATA DECODE ==========
function decodeEarlyData(header, userID) {
  if (!header || header.length > WS_EARLY_DATA_MAX_HEADER_LENGTH) {
    return null;
  }

  let bytes;

  // Try base64url decode
  const Uint8ArrayBase64 = Uint8Array;
  if (typeof Uint8ArrayBase64.fromBase64 === 'function') {
    try {
      bytes = Uint8ArrayBase64.fromBase64(header, { alphabet: 'base64url' });
    } catch (_) {}
  }

  // Manual base64 decode fallback
  if (!bytes) {
    let normalized = header.replace(/-/g, '+').replace(/_/g, '/');
    const padding = normalized.length % 4;
    if (padding) normalized += '='.repeat(4 - padding);

    try {
      const binary = atob(normalized);
      bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
    } catch (_) {
      return null;
    }
  }

  if (bytes.byteLength > WS_EARLY_DATA_MAX_BYTES) {
    return null;
  }

  // Validate VLESS request
  if (bytes.byteLength >= 18 && uuidBytesMatch(bytes, 1, userID)) {
    return bytes;
  }

  return null;
}

// ========== UTILITY FUNCTIONS ==========
function isSpeedTestSite(hostname) {
  const blocked = ['speed.cloudflare.com'];
  return blocked.includes(hostname) || blocked.some(d => hostname.endsWith('.' + d));
}

function log(...args) {
  if (CONFIG.LOG) console.log(...args);
}
