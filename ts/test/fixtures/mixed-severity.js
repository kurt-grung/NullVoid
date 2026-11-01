// Test file for mixed severity threats
const normalCode = "console.log('hello world');";

// This should be LOW severity (test file detection)
const testFunction = () => {
  console.log('This is a test function');
};

// This should be MEDIUM severity (suspicious module)
const fs = require('fs');

// This should be HIGH severity (obfuscated code)
const obfuscated = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6";

// This should be CRITICAL severity (malicious structure)
const hexArray = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64];

module.exports = { normalCode };
