// Root layout — required by the Next.js App Router. Kept dependency-free (no
// CSS import, no fonts) so `next build` needs nothing beyond next/react.
export const metadata = {
  title: "ship-fixture-nextjs",
  description: "getdev docker-build ship fixture",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
