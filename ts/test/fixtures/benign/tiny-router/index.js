'use strict';
const http = require('http');
const { URL } = require('url');

class Router {
  constructor() {
    this.routes = [];
  }
  get(pathname, handler) {
    this.routes.push({ method: 'GET', pathname, handler });
    return this;
  }
  post(pathname, handler) {
    this.routes.push({ method: 'POST', pathname, handler });
    return this;
  }
  handle(req, res) {
    const url = new URL(req.url, 'http://localhost');
    const route = this.routes.find((r) => r.method === req.method && r.pathname === url.pathname);
    if (!route) {
      res.statusCode = 404;
      return res.end('Not Found');
    }
    let body = '';
    req.on('data', (chunk) => (body += chunk));
    req.on('end', () => route.handler(req, res, body));
  }
  listen(port, cb) {
    return http.createServer((req, res) => this.handle(req, res)).listen(port, cb);
  }
}
module.exports = { Router };
