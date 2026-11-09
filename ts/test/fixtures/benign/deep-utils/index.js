'use strict';
function isObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}
function get(obj, path, fallback) {
  const parts = Array.isArray(path) ? path : String(path).split('.');
  let cur = obj;
  for (const p of parts) {
    if (cur == null) return fallback;
    cur = cur[p];
  }
  return cur === undefined ? fallback : cur;
}
function set(obj, path, value) {
  const parts = Array.isArray(path) ? path : String(path).split('.');
  let cur = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return obj;
    if (!isObject(cur[key])) cur[key] = {};
    cur = cur[key];
  }
  cur[parts[parts.length - 1]] = value;
  return obj;
}
function merge(target, ...sources) {
  for (const src of sources) {
    if (!isObject(src)) continue;
    for (const key of Object.keys(src)) {
      if (key === '__proto__' || key === 'constructor') continue;
      target[key] = isObject(src[key]) && isObject(target[key]) ? merge(target[key], src[key]) : src[key];
    }
  }
  return target;
}
function debounce(fn, wait) {
  let t;
  return function (...args) {
    clearTimeout(t);
    t = setTimeout(() => fn.apply(this, args), wait);
  };
}
module.exports = { isObject, get, set, merge, debounce };
