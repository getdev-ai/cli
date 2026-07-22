import type { Config } from 'tailwindcss'
import typography from '@tailwindcss/typography'

// gd-* design tokens — ported verbatim from the getdev gallery
// (getdev-ai/getdev · apps/web/tailwind.config.ts) so the CLI landing shares
// the family design system. CSS var values live in app/globals.css.

const config: Config = {
  content: ['./app/**/*.{ts,tsx,mdx}'],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        'gd-bg': 'var(--gd-bg)',
        'gd-surface': 'var(--gd-surface)',
        'gd-surface-2': 'var(--gd-surface-2)',
        'gd-border': 'var(--gd-border)',
        'gd-border-2': 'var(--gd-border-2)',
        'gd-border-light': 'var(--gd-border-light)',
        'gd-text-1': 'var(--gd-text-1)',
        'gd-text-2': 'var(--gd-text-2)',
        'gd-text-3': 'var(--gd-text-3)',
        'gd-accent': 'var(--gd-accent)',
        'gd-accent-hover': 'var(--gd-accent-hover)',
        'gd-accent-soft': 'var(--gd-accent-soft)',
        'gd-accent-ink': 'var(--gd-accent-ink)',
        'gd-primary': 'var(--gd-primary)',
        'gd-primary-ink': 'var(--gd-primary-ink)',
        'gd-primary-hover': 'var(--gd-primary-hover)',
        'gd-success': 'var(--gd-success)',
        'gd-warning': 'var(--gd-warning)',
        'gd-danger': 'var(--gd-danger)',
        'gd-info': 'var(--gd-info)',
        'gd-brand-mark': 'var(--gd-brand-mark)',
      },
      fontFamily: {
        sans: ['var(--font-sans)', 'system-ui', 'sans-serif'],
        mono: ['var(--font-mono)', 'ui-monospace', 'monospace'],
      },
      fontSize: {
        meta: ['11px', { lineHeight: '1.4', fontWeight: '500', letterSpacing: '0.02em' }],
        'body-sm': ['13px', { lineHeight: '1.5' }],
        body: ['15px', { lineHeight: '1.55' }],
        lead: ['18px', { lineHeight: '1.55' }],
        h3: ['17px', { lineHeight: '1.3', fontWeight: '600' }],
        h2: ['22px', { lineHeight: '1.25', fontWeight: '600' }],
        h1: ['32px', { lineHeight: '1.2', fontWeight: '700', letterSpacing: '-0.01em' }],
        display: ['56px', { lineHeight: '1.05', fontWeight: '700', letterSpacing: '-0.02em' }],
      },
      borderRadius: {
        sm: '4px',
        DEFAULT: '6px',
        md: '8px',
        lg: '12px',
        full: '9999px',
      },
      maxWidth: {
        feed: '1280px',
        reading: '720px',
      },
      boxShadow: {
        'gd-card': 'var(--gd-shadow-card)',
        'gd-card-hover': 'var(--gd-shadow-card-hover)',
      },
    },
  },
  plugins: [typography],
}

export default config
