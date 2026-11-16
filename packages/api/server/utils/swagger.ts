/** Swagger UI page shell and initializer (assets come from swagger-ui-dist). */
export function indexHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>NullVoid API docs</title>
  <link rel="stylesheet" href="./swagger-ui.css">
  <link rel="icon" type="image/png" href="./favicon-32x32.png" sizes="32x32">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="./swagger-ui-bundle.js"></script>
  <script src="./swagger-ui-standalone-preset.js"></script>
  <script src="./swagger-initializer.js"></script>
</body>
</html>`;
}

export const INITIALIZER = `window.onload = function () {
  var base = window.location.pathname.replace(/\\/api-docs\\/?.*$/, '');
  window.ui = SwaggerUIBundle({
    url: base + '/api-docs.json',
    dom_id: '#swagger-ui',
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    layout: 'StandaloneLayout'
  });
};`;

