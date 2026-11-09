'use strict';
const path = require('path');
const yaml = require('js-yaml');

/** webpack loader: turns a YAML file into a JSON module. */
module.exports = function yamlLoader(source) {
  const callback = this.async();
  try {
    const data = yaml.load(source, { filename: this.resourcePath });
    const name = path.basename(this.resourcePath);
    this.emitWarning && name.endsWith('.yml') && this.emitWarning(new Error('prefer .yaml'));
    callback(null, `export default ${JSON.stringify(data)};`);
  } catch (err) {
    callback(err);
  }
};
