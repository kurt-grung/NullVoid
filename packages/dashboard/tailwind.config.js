/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['Geist Variable', 'Geist', 'system-ui', 'sans-serif'],
        mono: ['Geist Mono Variable', 'Geist Mono', 'monospace'],
      },
      colors: {
        // Light – Vercel-style
        surface: '#ffffff',
        'surface-card': '#ffffff',
        'surface-muted': '#fafafa',
        'surface-border': '#eaeaea',
        // Dark – Vercel-style (true black)
        'dark-surface': '#000000',
        'dark-card': '#000000',
        'dark-muted': '#111111',
        'dark-border': '#222222',
      },
    },
  },
  plugins: [],
}
