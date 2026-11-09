'use strict';
/**
 * Babel plugin: removes `debugger` statements and console.debug calls.
 */
module.exports = function stripDebug({ types: t }) {
  return {
    name: 'strip-debug',
    visitor: {
      DebuggerStatement(path) {
        path.remove();
      },
      CallExpression(path) {
        const callee = path.get('callee');
        if (
          callee.isMemberExpression() &&
          t.isIdentifier(callee.node.object, { name: 'console' }) &&
          t.isIdentifier(callee.node.property, { name: 'debug' })
        ) {
          if (path.parentPath.isExpressionStatement()) path.parentPath.remove();
          else path.replaceWith(t.identifier('undefined'));
        }
      },
    },
  };
};
