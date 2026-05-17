import type { Config } from 'tailwindcss';

const config: Config = {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          surface: '#111827',
          muted: '#1f2937',
          border: '#374151',
          danger: '#ef4444',
          warning: '#f59e0b',
          success: '#22c55e',
          info: '#60a5fa',
          accent: '#38bdf8'
        }
      },
      boxShadow: {
        panel: '0 20px 60px rgba(15, 23, 42, 0.35)'
      }
    }
  },
  plugins: []
};

export default config;
