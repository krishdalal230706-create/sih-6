/** @type {import('tailwindcss').Config} */
export default {
  content: [
    './index.html',
    './src/**/*.{js,ts,jsx,tsx}'
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0B0F17',
          card: '#111726',
          border: '#1E293B',
          cyan: '#00F0FF',
          blue: '#3B82F6',
          red: '#FF3366',
          amber: '#FFB800',
          emerald: '#10B981',
          slate: '#94A3B8'
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Menlo', 'Monaco', 'Consolas', 'monospace']
      }
    }
  },
  plugins: []
};
