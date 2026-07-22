// Root layout for the getdev.ai CLI landing (static export → Cloudflare Pages).
// Inter for UI/body, JetBrains Mono for code/data — matching the getdev family
// design system. The site is dark-only, so data-theme="dark" is set on <html>.

import type { Metadata } from 'next'
import { Inter, JetBrains_Mono } from 'next/font/google'
import './globals.css'

const sans = Inter({
  subsets: ['latin'],
  variable: '--font-sans',
  display: 'swap',
})

const mono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
  display: 'swap',
})

export const metadata: Metadata = {
  metadataBase: new URL('https://getdev.ai'),
  title: 'getdev — verify, secure, and ship AI-generated code',
  description:
    'The free, open-source CLI toolbelt for AI-generated code. One command — getdev check — gives a deterministic Ship Score across hallucinated packages, hardcoded secrets, AI-pattern security holes, and agent debris. One static binary, runs locally, nothing leaves your machine. Apache-2.0.',
  applicationName: 'getdev',
  keywords: [
    'getdev',
    'AI code',
    'CLI',
    'static analysis',
    'secret scanning',
    'slopsquatting',
    'security',
    'Rust',
    'vibe coding',
  ],
  alternates: { canonical: 'https://getdev.ai' },
  openGraph: {
    type: 'website',
    url: 'https://getdev.ai',
    siteName: 'getdev',
    title: 'getdev — verify, secure, and ship AI-generated code',
    description:
      'The free, open-source CLI toolbelt for AI-generated code. One command gives a deterministic Ship Score. Runs locally, nothing leaves your machine. Apache-2.0.',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'getdev — verify, secure, and ship AI-generated code',
    description:
      'The free, open-source CLI toolbelt for AI-generated code. One command, one Ship Score. Runs locally. Apache-2.0.',
  },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark" className={`${sans.variable} ${mono.variable}`}>
      <body className="bg-gd-bg font-sans text-gd-text-1 antialiased">{children}</body>
    </html>
  )
}
