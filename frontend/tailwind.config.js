/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx,ts,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      colors: {
        'neon-red':    '#ef4444',
        'neon-green':  '#22c55e',
        'neon-blue':   '#3b82f6',
        'neon-cyan':   '#06b6d4',
        'neon-orange': '#f97316',
        'neon-purple': '#a855f7',
      },
      animation: {
        'pulse-glow':   'pulse-glow 2s ease-in-out infinite',
        'danger-pulse': 'danger-pulse 1.5s ease-in-out infinite',
        'node-pulse':   'node-pulse 2s ease-in-out infinite',
        'fade-in-up':   'fade-in-up 0.5s ease-out forwards',
        'spin-slow':    'spin-slow 1.5s linear infinite',
        'data-ticker':  'data-ticker 1.2s ease-in-out infinite',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { boxShadow: '0 0 4px 1px #22c55e80, 0 0 8px 2px #22c55e80' },
          '50%':       { boxShadow: '0 0 12px 4px #22c55e80, 0 0 24px 8px #22c55e80' },
        },
        'danger-pulse': {
          '0%, 100%': { boxShadow: '0 0 6px 2px #ef444480, 0 0 16px 4px #ef444480' },
          '50%':       { boxShadow: '0 0 20px 8px #ef444480, 0 0 40px 12px #ef444480' },
        },
        'node-pulse': {
          '0%, 100%': { transform: 'scale(1)', opacity: '1' },
          '50%':       { transform: 'scale(1.3)', opacity: '0.7' },
        },
        'fade-in-up': {
          from: { opacity: '0', transform: 'translateY(20px)' },
          to:   { opacity: '1', transform: 'translateY(0)' },
        },
        'spin-slow': {
          from: { transform: 'rotate(0deg)' },
          to:   { transform: 'rotate(360deg)' },
        },
        'data-ticker': {
          '0%, 100%': { opacity: '0.3' },
          '50%':       { opacity: '1' },
        },
      },
    },
  },
  plugins: [],
};
