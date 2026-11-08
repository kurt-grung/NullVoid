// LOW: a lone child_process use, informational only (shown with --all)
const { execSync } = require('child_process');
module.exports = { version: () => execSync('git --version').toString() };
