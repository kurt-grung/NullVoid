/**
 * Raw ANSI color codes for terminal output
 * Eliminates supply chain risk from compromised packages
 */

const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  gray: '\x1b[90m'
};

const color = {
  // Basic colors
  red: (text) => `${colors.red}${text}${colors.reset}`,
  green: (text) => `${colors.green}${text}${colors.reset}`,
  yellow: (text) => `${colors.yellow}${text}${colors.reset}`,
  blue: (text) => `${colors.blue}${text}${colors.reset}`,
  magenta: (text) => `${colors.magenta}${text}${colors.reset}`,
  cyan: (text) => `${colors.cyan}${text}${colors.reset}`,
  white: (text) => `${colors.white}${text}${colors.reset}`,
  gray: (text) => `${colors.gray}${text}${colors.reset}`,
  
  // Bold colors
  bold: (text) => `${colors.bold}${text}${colors.reset}`
};

// Add combined styles after the main object
color.red.bold = (text) => `${colors.bold}${colors.red}${text}${colors.reset}`;
color.green.bold = (text) => `${colors.bold}${colors.green}${text}${colors.reset}`;
color.yellow.bold = (text) => `${colors.bold}${colors.yellow}${text}${colors.reset}`;
color.blue.bold = (text) => `${colors.bold}${colors.blue}${text}${colors.reset}`;

module.exports = color;
