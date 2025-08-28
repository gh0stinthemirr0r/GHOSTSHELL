/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{html,js,svelte,ts}'],
  theme: {
    extend: {
      colors: {
        // Cyberpunk Neon Theme (CSS variables will override these)
        'ghost-bg': 'rgba(12,15,28,var(--tw-bg-opacity))',
        'ghost-fg': '#EAEAEA',
        'ghost-slate': '#2B2B2E',
        'ghost-pink': '#FF008C',
        'ghost-cyan': '#00FFD1',
        'ghost-neon': '#AFFF00',
        'ghost-border': 'rgba(255,255,255,0.10)',
      },
      fontFamily: {
        'mono': ['var(--font-mono)', 'JetBrainsMono Nerd Font', 'Fira Code', 'monospace'],
        'ui': ['var(--font-ui)', 'Inter', 'system-ui', 'sans-serif'],
      },
      backdropBlur: {
        'ghost': '18px',
      },
      animation: {
        'glow-pulse': 'glow-pulse 2s ease-in-out infinite alternate',
        'slide-in-right': 'slide-in-right 0.2s ease-out',
        'slide-out-right': 'slide-out-right 0.2s ease-in',
      },
      keyframes: {
        'glow-pulse': {
          '0%': { 
            'box-shadow': '0 0 5px currentColor, 0 0 10px currentColor, 0 0 15px currentColor',
            'filter': 'brightness(1)'
          },
          '100%': { 
            'box-shadow': '0 0 10px currentColor, 0 0 20px currentColor, 0 0 30px currentColor',
            'filter': 'brightness(1.2)'
          }
        },
        'slide-in-right': {
          '0%': { transform: 'translateX(100%)' },
          '100%': { transform: 'translateX(0)' }
        },
        'slide-out-right': {
          '0%': { transform: 'translateX(0)' },
          '100%': { transform: 'translateX(100%)' }
        }
      }
    },
  },
  plugins: [],
}
