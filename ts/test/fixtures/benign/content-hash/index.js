'use strict';
const crypto = require('crypto');
const fs = require('fs');

function hashString(input, algorithm = 'sha256') {
  return crypto.createHash(algorithm).update(input).digest('hex');
}
function hashFile(file, algorithm = 'sha256') {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash(algorithm);
    fs.createReadStream(file).on('data', (d) => hash.update(d)).on('end', () => resolve(hash.digest('hex'))).on('error', reject);
  });
}
function shortHash(input, length = 8) {
  return hashString(input).slice(0, length);
}
module.exports = { hashString, hashFile, shortHash };
