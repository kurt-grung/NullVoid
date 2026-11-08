'use strict';
const { useState, useCallback } = require('react');

function useToggle(initial = false) {
  const [on, setOn] = useState(Boolean(initial));
  const toggle = useCallback(() => setOn((v) => !v), []);
  const setTrue = useCallback(() => setOn(true), []);
  const setFalse = useCallback(() => setOn(false), []);
  return [on, { toggle, setTrue, setFalse }];
}
module.exports = { useToggle };
