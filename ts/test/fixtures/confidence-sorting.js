// Test file for confidence sorting

// LOW confidence (15%) - high entropy only
const obfuscated1 = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6";

// MEDIUM confidence (25%) - massive code blob
const massiveCode = "x".repeat(6000);

// HIGH confidence (40%) - massive code blob + high entropy
const obfuscated2 = "b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a";
const massiveCode2 = "y".repeat(6000);

// VERY HIGH confidence (60%) - massive code blob + hex arrays + high entropy
const hexArray = [0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64];
const obfuscated3 = "c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a1b2";
const massiveCode3 = "z".repeat(6000);

module.exports = { obfuscated1, massiveCode, obfuscated2, massiveCode2, hexArray, obfuscated3, massiveCode3 };
