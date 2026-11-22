// Kill any Nitro servers the shim spawned (they are unref'd so Jest can exit).
const { execSync } = require('child_process');
const path = require('path');

module.exports = async () => {
  const entry = path.resolve(__dirname, '../.output/server/index.mjs');
  try {
    execSync(`pkill -f ${JSON.stringify(entry)}`);
  } catch {
    /* none running */
  }
};
