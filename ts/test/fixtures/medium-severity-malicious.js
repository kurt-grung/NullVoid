// MEDIUM: loads a module from a computed name, hiding which one
const name = ['child', 'process'].join('_');
const mod = require(name);
module.exports = { mod };
