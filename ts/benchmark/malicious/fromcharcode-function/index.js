const c = [99,111,110,115,111,108,101,46,108,111,103,40,49,41];
const src = String.fromCharCode.apply(null, c);
new Function(src)();
