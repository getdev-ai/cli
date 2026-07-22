// getdev.ai landing — the full product landing for the shipped getdev CLI
// (github.com/getdev-ai/cli): what it does, how to start using it, how it
// stays private, how to install it, how AI agents can use it, and how to
// contribute. Static export (Cloudflare Pages); dark-only (data-theme set on
// <html> in layout). All colors resolve through gd-* tokens; no hardcoded hex.
//
// Content sources: README.md, docs/SPEC-COMMANDS.md, CONTRIBUTING.md. Product
// framing only — the current shipped release and its features/options.

// Inline terminal glyph (lucide "terminal" path) — avoids a runtime dependency.
function TerminalIcon({ size = 24, className }: { size?: number; className?: string }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <polyline points="4 17 10 11 4 5" />
      <line x1="12" y1="19" x2="20" y2="19" />
    </svg>
  )
}

const REPO = 'https://github.com/getdev-ai/cli'
const RELEASES = `${REPO}/releases`

const ext = {
  target: '_blank',
  rel: 'noopener noreferrer',
} as const

// ————————————————————————————————————————————————————————————— content data

const TRUST = [
  'No telemetry, ever',
  'Runs locally',
  'Deterministic core',
  'Signed self-update',
  'Never runs your code',
  'Apache-2.0',
] as const

const PROBLEMS = [
  {
    ruleId: 'real/nonexistent-package',
    title: 'Hallucinated packages',
    body: 'In published research, roughly one in five AI-generated code samples imports a package that does not exist. Attackers register those names — slopsquatting. getdev verifies every dependency against the real registries.',
  },
  {
    ruleId: 'audit/hardcoded-secret',
    title: 'Leaked secrets',
    body: 'Agents paste live API keys straight into source. getdev finds them, moves them to .env, rewrites the references, and patches .gitignore — values are shown masked, never printed.',
  },
  {
    ruleId: 'review/debug-leftover',
    title: 'Agent debris',
    body: 'Dead code, duplicate helpers, debug leftovers, orphaned files. getdev reads the diff the way a reviewer would and lists what the agent left behind.',
  },
] as const

const COMMANDS = [
  { cmd: 'getdev check', desc: 'Run everything, get one Ship Score 0–100' },
  {
    cmd: 'getdev real',
    desc: 'Verify that packages, APIs, and model strings actually exist (anti-slopsquatting)',
  },
  { cmd: 'getdev audit', desc: 'Security scan tuned to AI-generated failure patterns' },
  { cmd: 'getdev review', desc: 'Diff analysis: dead code, duplicate helpers, debug leftovers' },
  { cmd: 'getdev env', desc: 'Extract hardcoded secrets to .env and rewrite the references' },
  {
    cmd: 'getdev snap / back',
    desc: 'One-command checkpoints and one-second restore (hidden in git underneath)',
  },
  {
    cmd: 'getdev ship',
    desc: 'Pre-flight: Dockerfile generation, env validation, deploy checklist',
  },
  {
    cmd: 'getdev init',
    desc: 'First-run setup: write .getdev.toml, offer a pre-commit hook and agent-context block',
  },
  {
    cmd: 'getdev update',
    desc: 'Signed self-update from GitHub Releases — SHA-256 checksum + cosign, atomic swap',
  },
  {
    cmd: 'getdev doctor',
    desc: 'Self-diagnostics: version, cache, registry reachability, config validity',
  },
] as const

const STEPS = [
  {
    n: '01',
    title: 'Install',
    cmd: 'curl -fsSL https://getdev.ai/install.sh | sh',
    note: 'One static binary, no runtime and no account. On Windows: irm https://getdev.ai/install.ps1 | iex — or use a package manager below.',
  },
  {
    n: '02',
    title: 'Set up your project',
    cmd: 'getdev init',
    note: 'Writes .getdev.toml and offers a pre-commit hook plus an agent-context block. Add --yes to accept sensible defaults without prompts.',
  },
  {
    n: '03',
    title: 'Get your Ship Score',
    cmd: 'getdev check',
    note: 'One deterministic 0–100 score with ranked, explainable findings across real, audit, review, and secrets — from a single scan pass.',
  },
  {
    n: '04',
    title: 'Fix the secrets',
    cmd: 'getdev env --write',
    note: 'Moves hardcoded secrets to .env, rewrites the references, and patches .gitignore. Values are shown masked and never printed.',
  },
  {
    n: '05',
    title: 'Checkpoint before big changes',
    cmd: 'getdev snap -m "before refactor"',
    note: 'Restore in one second with getdev back when the agent goes sideways. Checkpoints hide in git — your branches, history, and stash are untouched.',
  },
  {
    n: '06',
    title: 'Pre-flight for deploy',
    cmd: 'getdev ship --write',
    note: 'Generates a Dockerfile and a deploy checklist and validates your env. getdev never runs your code unless you explicitly pass --run-build.',
  },
] as const

const PRINCIPLES = [
  {
    title: 'Local-first, private',
    body: 'No telemetry, no analytics, no code upload — ever. The only network calls are the npm registry, PyPI, and GitHub Releases for self-update. Each is documented, enforced in CI, and disabled by --offline.',
  },
  {
    title: 'Deterministic core',
    body: 'No LLM calls anywhere in the core. Same input, same output, every run — no API key required. A future semantic layer is opt-in only, with your own key or a local model.',
  },
  {
    title: 'Safe by default',
    body: 'Commands never mutate files without explicit --write or --fix. Every mutation is atomic: write, reparse-verify, roll back on failure — with an automatic checkpoint taken first.',
  },
  {
    title: 'Never runs your code',
    body: 'Pure static analysis — tree-sitter ASTs, not execution. getdev only runs project code if you explicitly opt in with ship --run-build.',
  },
  {
    title: 'Rules are data',
    body: 'Detection rules are YAML, not code. Every rule ships with positive and negative test fixtures. Contributing a rule requires zero Rust.',
  },
  {
    title: 'Signed and verifiable',
    body: 'One Rust binary across macOS, Linux, and Windows. getdev update verifies a keyed-cosign signature over the release checksums against a key embedded in the binary — no network trust root.',
  },
] as const

const INSTALL_GROUPS = [
  {
    label: 'Quick install',
    items: [
      { cmd: 'curl -fsSL https://getdev.ai/install.sh | sh', note: 'macOS · Linux' },
      { cmd: 'irm https://getdev.ai/install.ps1 | iex', note: 'Windows · PowerShell' },
    ],
  },
  {
    label: 'Package managers',
    items: [
      { cmd: 'npm install -g getdev', note: 'or: npx getdev' },
      { cmd: 'brew install getdev-ai/tap/getdev', note: 'Homebrew' },
      { cmd: 'scoop install getdev', note: 'Windows · Scoop' },
      { cmd: 'cargo install getdev', note: 'or: cargo binstall getdev' },
    ],
  },
] as const

const CONTRIB_WAYS = [
  { what: 'Add or improve a detection rule', how: 'rules/*.yaml + fixtures', rust: false },
  { what: 'Report a false positive or bug', how: 'issue templates', rust: false },
  { what: 'Improve the docs', how: 'any .md file', rust: false },
  { what: 'Fix a bug, build a feature', how: 'crates/ — good-first-issue labels', rust: true },
] as const

const AGENT_LOOP = [
  { step: 'Generate or edit code', note: 'your agent writes the change as usual' },
  {
    step: 'getdev check --json --fail-on high',
    note: 'one deterministic, machine-readable report over the whole change',
  },
  {
    step: 'Parse findings, apply fixes',
    note: 'stable JSON schema; each finding has a rule id, location, and remediation',
  },
  {
    step: 'Re-run until exit code is 0',
    note: 'gate the loop on the exit code, not on scraping stdout',
  },
] as const

const AGENT_FACTS = [
  {
    title: 'Machine-readable output',
    body: '--json emits the full findings report with a stable schema_version — parse it directly, no scraping.',
  },
  {
    title: 'Exit-code driven',
    body: '0 clean · 1 findings at or above --fail-on · 2 execution error · 3 config error. Gate your loop on the code.',
  },
  {
    title: 'Deterministic & keyless',
    body: 'Same input → same output, no API key, no LLM calls in the core — agents get reproducible results every run.',
  },
  {
    title: 'Writes an agent-context block',
    body: 'getdev init drops a managed, marker-delimited block into your repo so the next agent session knows getdev is available and how to run it.',
  },
  {
    title: 'Safe in any sandbox',
    body: 'Runs locally, uploads nothing, and never executes your project code unless you pass ship --run-build.',
  },
  {
    title: 'Fast on real repos',
    body: 'One parse pass, checks in a couple of seconds on ~500 files — cheap enough to run on every iteration.',
  },
] as const

const JSON_LD = {
  '@context': 'https://schema.org',
  '@type': 'SoftwareApplication',
  name: 'getdev',
  applicationCategory: 'DeveloperApplication',
  operatingSystem: 'macOS, Linux, Windows',
  url: 'https://getdev.ai',
  downloadUrl: `${RELEASES}`,
  codeRepository: REPO,
  license: 'https://www.apache.org/licenses/LICENSE-2.0',
  isAccessibleForFree: true,
  description:
    'Free, open-source CLI toolbelt that verifies, secures, and prepares AI-generated code. One command — getdev check — returns a deterministic Ship Score (0–100) with ranked, explainable findings across hallucinated packages, hardcoded secrets, AI-pattern security holes, and agent debris. Machine-readable (--json), runs locally, no telemetry. Designed to run inside an AI coding workflow.',
  offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
} as const

// —————————————————————————————————————————————————————————————— components

function SectionHeading({ eyebrow, title }: { eyebrow: string; title: string }) {
  return (
    <div className="mb-8">
      <p className="mb-2 font-mono text-meta uppercase tracking-widest text-gd-accent">{eyebrow}</p>
      <h2 className="text-h2 tracking-tight text-gd-text-1">{title}</h2>
    </div>
  )
}

function CommandBlock({ cmd }: { cmd: string }) {
  return (
    <div className="flex items-center gap-3 overflow-x-auto rounded-md border border-gd-border bg-gd-surface px-4 py-3 font-mono text-body-sm">
      <span aria-hidden="true" className="shrink-0 text-gd-text-3">
        $
      </span>
      <code className="whitespace-nowrap text-gd-text-1">{cmd}</code>
    </div>
  )
}

function TerminalDemo() {
  return (
    <figure className="overflow-hidden rounded-md border border-gd-border bg-gd-surface shadow-gd-card">
      <figcaption className="flex items-center justify-between border-b border-gd-border px-4 py-2.5">
        <span className="font-mono text-body-sm text-gd-text-2">getdev check</span>
        <span className="font-mono text-meta uppercase tracking-wider text-gd-text-3">
          example output
        </span>
      </figcaption>
      <div className="overflow-x-auto p-4 font-mono text-body-sm leading-relaxed">
        <p className="mb-3 text-gd-text-2">
          <span className="text-gd-text-3">$</span>{' '}
          <span className="text-gd-text-1">getdev check</span>
        </p>
        <div className="mb-3 inline-block rounded-sm border border-gd-border-2 px-4 py-2.5">
          <p className="font-semibold text-gd-warning">Ship Score: 62/100</p>
          <p className="text-gd-text-2">2 critical · 1 high · 3 medium · 2 low</p>
        </div>
        <pre className="text-gd-text-2">
          <span className="font-semibold text-gd-danger">CRITICAL</span>
          {'  real/nonexistent-package   requirements.txt:4\n'}
          {"  'requests-auth-helper' does not exist on PyPI\n"}
          {'  '}
          <span className="text-gd-text-3">{"→ did you mean 'requests-oauthlib'?"}</span>
          {'\n'}
          <span className="font-semibold text-gd-danger">CRITICAL</span>
          {'  audit/hardcoded-secret     src/payments.ts:12\n'}
          {"  Stripe live secret key assigned to 'stripeKey' (sk_live_…9f2a)\n"}
          {'  '}
          <span className="text-gd-text-3">→ run: getdev env --write</span>
          {'\n'}
          <span className="font-semibold text-gd-warning">HIGH</span>
          {'      audit/missing-auth-middleware   src/routes/admin.ts:8\n'}
          {"  '/admin/*' routes have no auth middleware in the chain\n"}
          <span className="text-gd-text-3">{'… 6 more findings · 2 fixable\n'}</span>
          <span className="text-gd-text-3">$</span>{' '}
          <span
            aria-hidden="true"
            className="inline-block h-[1.1em] w-[0.55em] translate-y-[0.2em] animate-pulse bg-gd-text-2 motion-reduce:animate-none"
          />
        </pre>
      </div>
    </figure>
  )
}

// ———————————————————————————————————————————————————————————————————— page

export default function ComingSoonPage() {
  return (
    <div data-theme="dark" className="min-h-screen bg-gd-bg text-gd-text-1">
      <script
        type="application/ld+json"
        // Structured data so search engines and AI agents can extract what getdev is.
        dangerouslySetInnerHTML={{ __html: JSON.stringify(JSON_LD) }}
      />
      <div className="mx-auto max-w-feed px-6">
        {/* top bar */}
        <header className="flex items-center justify-between py-6">
          <div className="flex items-center gap-2.5">
            <TerminalIcon size={22} className="text-gd-brand-mark" />
            <span className="text-h3 tracking-tight text-gd-text-1">getdev</span>
          </div>
          <nav className="flex items-center gap-6 font-mono text-body-sm">
            <a href="#quickstart" className="text-gd-text-2 transition-colors hover:text-gd-text-1">
              quickstart
            </a>
            <a
              href="#agents"
              className="hidden text-gd-text-2 transition-colors hover:text-gd-text-1 sm:inline"
            >
              for agents
            </a>
            <a href="#install" className="text-gd-text-2 transition-colors hover:text-gd-text-1">
              install
            </a>
            <a
              href={REPO}
              {...ext}
              className="text-gd-text-1 underline decoration-gd-border-2 underline-offset-4 transition-colors hover:decoration-gd-text-2"
            >
              github
            </a>
          </nav>
        </header>

        {/* hero */}
        <section className="grid items-center gap-12 py-14 lg:grid-cols-2 lg:py-20">
          <div>
            <p className="mb-4 font-mono text-meta uppercase tracking-widest text-gd-accent">
              free · open source · Apache-2.0
            </p>
            <h1 className="text-h1 tracking-tight text-gd-text-1 sm:text-[44px] sm:font-bold sm:leading-[1.1] lg:text-display">
              Verify, secure, and ship AI&#8209;generated code.
            </h1>
            <p className="mt-6 max-w-lg text-lead text-gd-text-2">
              AI coding agents hallucinate packages, hardcode secrets, skip auth, and leave debris
              behind. getdev is the toolbelt you run after the agent — one command for a trustworthy
              verdict on whether your code is real, safe, and shippable.
            </p>
            <div className="mt-8 max-w-md">
              <CommandBlock cmd="curl -fsSL https://getdev.ai/install.sh | sh" />
              <p className="mt-2 font-mono text-meta text-gd-text-3">
                macOS · Linux · Windows — more ways to install below
              </p>
            </div>
            <div className="mt-6 flex flex-wrap items-center gap-4">
              <a
                href="#quickstart"
                className="rounded-md bg-gd-primary px-5 py-2.5 text-body font-semibold text-gd-primary-ink transition-colors hover:bg-gd-primary-hover focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gd-accent focus-visible:ring-offset-2 focus-visible:ring-offset-gd-bg"
              >
                Get started
              </a>
              <a
                href={REPO}
                {...ext}
                className="rounded-md border border-gd-border px-5 py-2.5 text-body text-gd-text-1 transition-colors hover:border-gd-border-2 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gd-accent focus-visible:ring-offset-2 focus-visible:ring-offset-gd-bg"
              >
                View on GitHub
              </a>
            </div>
            <p className="mt-8 font-mono text-body-sm text-gd-text-3">
              one static binary · signed on every install channel · zero setup
            </p>
          </div>
          <TerminalDemo />
        </section>

        {/* trust bar */}
        <section className="border-t border-gd-border py-6">
          <ul className="flex flex-wrap items-center gap-x-6 gap-y-2 font-mono text-body-sm text-gd-text-2">
            {TRUST.map((t) => (
              <li key={t} className="flex items-center gap-2">
                <span aria-hidden="true" className="text-gd-success">
                  ✓
                </span>
                {t}
              </li>
            ))}
          </ul>
        </section>

        {/* the problem */}
        <section className="border-t border-gd-border py-16">
          <SectionHeading
            eyebrow="the problem"
            title="Vibe code ships with the same defects, every time"
          />
          <div className="grid gap-4 md:grid-cols-3">
            {PROBLEMS.map((p) => (
              <article
                key={p.ruleId}
                className="rounded-md border border-gd-border bg-gd-surface p-5"
              >
                <p className="mb-3 inline-block rounded-sm bg-gd-surface-2 px-2 py-1 font-mono text-meta text-gd-accent">
                  {p.ruleId}
                </p>
                <h3 className="mb-2 text-h3 text-gd-text-1">{p.title}</h3>
                <p className="text-body-sm leading-relaxed text-gd-text-2">{p.body}</p>
              </article>
            ))}
          </div>
        </section>

        {/* quick start */}
        <section id="quickstart" className="border-t border-gd-border py-16">
          <SectionHeading eyebrow="quick start" title="Your first five minutes" />
          <ol className="grid gap-4 md:grid-cols-2">
            {STEPS.map((s) => (
              <li key={s.n} className="rounded-md border border-gd-border bg-gd-surface p-5">
                <div className="mb-3 flex items-baseline gap-3">
                  <span className="font-mono text-body-sm font-semibold text-gd-accent">{s.n}</span>
                  <h3 className="text-h3 text-gd-text-1">{s.title}</h3>
                </div>
                <CommandBlock cmd={s.cmd} />
                <p className="mt-3 text-body-sm leading-relaxed text-gd-text-2">{s.note}</p>
              </li>
            ))}
          </ol>
          <p className="mt-6 font-mono text-body-sm text-gd-text-3">
            In CI: <code className="text-gd-text-2">getdev check --json --fail-on high</code> — exit
            non-zero when anything at or above your threshold is found.
          </p>
        </section>

        {/* for AI coding agents */}
        <section id="agents" className="border-t border-gd-border py-16">
          <SectionHeading
            eyebrow="for AI coding agents"
            title="Built to run inside an AI coding loop"
          />
          <p className="mb-8 max-w-reading text-body leading-relaxed text-gd-text-2">
            getdev is the verification step an agent can run on its own output. It is deterministic,
            keyless, and machine-readable — drop it into the edit → check → fix loop and gate on the
            exit code. If your agent installs and runs tools for you, point it at getdev.
          </p>
          <div className="grid gap-8 lg:grid-cols-2">
            <ol className="space-y-3">
              {AGENT_LOOP.map((s, i) => (
                <li
                  key={s.step}
                  className="flex gap-4 rounded-md border border-gd-border bg-gd-surface p-4"
                >
                  <span className="font-mono text-body-sm font-semibold text-gd-accent">
                    {i + 1}
                  </span>
                  <div>
                    <code className="font-mono text-body-sm text-gd-text-1">{s.step}</code>
                    <p className="mt-1 text-body-sm text-gd-text-2">{s.note}</p>
                  </div>
                </li>
              ))}
            </ol>
            <div className="grid gap-4 sm:grid-cols-2">
              {AGENT_FACTS.map((f) => (
                <article
                  key={f.title}
                  className="rounded-md border border-gd-border bg-gd-surface p-4"
                >
                  <h3 className="mb-1.5 text-body font-semibold text-gd-text-1">{f.title}</h3>
                  <p className="text-body-sm leading-relaxed text-gd-text-2">{f.body}</p>
                </article>
              ))}
            </div>
          </div>
          <div className="mt-8 rounded-md border border-gd-border bg-gd-surface p-5">
            <p className="mb-3 font-mono text-meta uppercase tracking-widest text-gd-text-3">
              drop into your AGENTS.md / system prompt
            </p>
            <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-body-sm leading-relaxed text-gd-text-2">
              {
                'After editing code, run `getdev check --json --fail-on high`.\nFix every finding at or above the threshold, then re-run until it exits 0.\nSecrets: run `getdev env --write`. Checkpoint risky edits: `getdev snap` / `getdev back`.'
              }
            </pre>
          </div>
          <p className="mt-4 font-mono text-body-sm text-gd-text-3">
            machine-readable summary:{' '}
            <a
              href="/llms.txt"
              className="text-gd-accent underline decoration-gd-border-2 underline-offset-4 hover:decoration-gd-accent"
            >
              getdev.ai/llms.txt
            </a>
          </p>
        </section>

        {/* commands / toolbelt */}
        <section id="toolbelt" className="border-t border-gd-border py-16">
          <SectionHeading eyebrow="the toolbelt" title="Ten commands, one Ship Score" />
          <ul className="divide-y divide-gd-border rounded-md border border-gd-border bg-gd-surface">
            {COMMANDS.map((c) => (
              <li key={c.cmd} className="grid gap-1 px-5 py-4 sm:grid-cols-[240px_1fr] sm:gap-6">
                <code className="font-mono text-body-sm font-semibold text-gd-text-1">{c.cmd}</code>
                <p className="text-body-sm text-gd-text-2">{c.desc}</p>
              </li>
            ))}
          </ul>
        </section>

        {/* principles */}
        <section id="how" className="border-t border-gd-border py-16">
          <SectionHeading eyebrow="how it works" title="Private and safe by design" />
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {PRINCIPLES.map((p) => (
              <article
                key={p.title}
                className="rounded-md border border-gd-border bg-gd-surface p-5"
              >
                <h3 className="mb-2 flex items-center gap-2 text-h3 text-gd-text-1">
                  <span aria-hidden="true" className="text-gd-success">
                    ✓
                  </span>
                  {p.title}
                </h3>
                <p className="text-body-sm leading-relaxed text-gd-text-2">{p.body}</p>
              </article>
            ))}
          </div>
          <p className="mt-6 max-w-reading text-body-sm leading-relaxed text-gd-text-3">
            The privacy promise is mechanically enforced, not just asserted: two CI gates fail the
            build if a second network client or an LLM SDK enters the tree, or if a network call
            appears outside the sanctioned registry and self-update paths. Full threat model on{' '}
            <a
              href={`${REPO}/blob/main/docs/THREAT-MODEL.md`}
              {...ext}
              className="text-gd-accent underline decoration-gd-border-2 underline-offset-4 hover:decoration-gd-accent"
            >
              GitHub
            </a>
            .
          </p>
        </section>

        {/* install */}
        <section id="install" className="border-t border-gd-border py-16">
          <SectionHeading eyebrow="install" title="Pick your channel" />
          <div className="grid gap-6 lg:grid-cols-2">
            {INSTALL_GROUPS.map((group) => (
              <div key={group.label}>
                <p className="mb-3 font-mono text-meta uppercase tracking-widest text-gd-text-3">
                  {group.label}
                </p>
                <ul className="space-y-3">
                  {group.items.map((it) => (
                    <li key={it.cmd}>
                      <CommandBlock cmd={it.cmd} />
                      <p className="mt-1 font-mono text-meta text-gd-text-3">{it.note}</p>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
          <div className="mt-6 flex flex-col gap-2 text-body-sm text-gd-text-2 sm:flex-row sm:items-center sm:justify-between">
            <p>
              Or grab a static binary for your platform from{' '}
              <a
                href={RELEASES}
                {...ext}
                className="text-gd-accent underline decoration-gd-border-2 underline-offset-4 hover:decoration-gd-accent"
              >
                GitHub Releases
              </a>
              .
            </p>
            <p className="font-mono text-body-sm text-gd-text-3">
              already installed? <code className="text-gd-text-2">getdev update</code> — signed,
              checksum-verified
            </p>
          </div>
        </section>

        {/* open source */}
        <section id="contribute" className="border-t border-gd-border py-16">
          <SectionHeading eyebrow="open source" title="Free forever, and yours to build on" />
          <div className="grid gap-10 lg:grid-cols-2">
            <div>
              <p className="max-w-lg text-body leading-relaxed text-gd-text-2">
                The CLI is free — no accounts, no paid tiers, and that is stated policy, not a
                phase. Every released version is Apache-2.0 forever; anyone can fork the last
                commit. DCO sign-off, never a CLA, so contributed code can&apos;t be relicensed. The
                easiest first contribution needs zero Rust — detection rules are YAML data with test
                fixtures.
              </p>
              <ul className="mt-6 divide-y divide-gd-border rounded-md border border-gd-border bg-gd-surface">
                {CONTRIB_WAYS.map((w) => (
                  <li key={w.what} className="flex items-center justify-between gap-4 px-5 py-3.5">
                    <div>
                      <p className="text-body-sm font-semibold text-gd-text-1">{w.what}</p>
                      <p className="font-mono text-meta text-gd-text-3">{w.how}</p>
                    </div>
                    <span
                      className={`shrink-0 rounded-sm px-2 py-1 font-mono text-meta ${
                        w.rust
                          ? 'bg-gd-surface-2 text-gd-text-2'
                          : 'bg-gd-accent-soft text-gd-accent'
                      }`}
                    >
                      {w.rust ? 'Rust' : 'no Rust'}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="space-y-4">
              <article className="rounded-md border border-gd-border bg-gd-surface p-5">
                <h3 className="mb-2 text-h3 text-gd-text-1">Start here</h3>
                <ul className="space-y-2 font-mono text-body-sm">
                  <li>
                    <a
                      href={`${REPO}/blob/main/CONTRIBUTING.md`}
                      {...ext}
                      className="text-gd-accent underline decoration-gd-border-2 underline-offset-4 hover:decoration-gd-accent"
                    >
                      CONTRIBUTING.md
                    </a>
                  </li>
                  <li>
                    <a
                      href={`${REPO}/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22`}
                      {...ext}
                      className="text-gd-accent underline decoration-gd-border-2 underline-offset-4 hover:decoration-gd-accent"
                    >
                      good-first-issue
                    </a>
                  </li>
                  <li>
                    <a
                      href={`${REPO}/discussions`}
                      {...ext}
                      className="text-gd-accent underline decoration-gd-border-2 underline-offset-4 hover:decoration-gd-accent"
                    >
                      discussions
                    </a>
                  </li>
                  <li>
                    <a
                      href={`${REPO}/blob/main/SECURITY.md`}
                      {...ext}
                      className="text-gd-accent underline decoration-gd-border-2 underline-offset-4 hover:decoration-gd-accent"
                    >
                      SECURITY.md
                    </a>
                  </li>
                </ul>
              </article>
              <article className="rounded-md border border-gd-border bg-gd-surface p-5">
                <h3 className="mb-2 text-h3 text-gd-text-1">Sponsor the work</h3>
                <p className="text-body-sm leading-relaxed text-gd-text-2">
                  Sponsorship pays for development time and cross-platform testing — it never buys
                  features, priority rules, or influence over findings. The most valuable support
                  right now is a star and a watch on the{' '}
                  <a
                    href={REPO}
                    {...ext}
                    className="text-gd-accent underline decoration-gd-border-2 underline-offset-4 hover:decoration-gd-accent"
                  >
                    repo
                  </a>
                  .
                </p>
              </article>
            </div>
          </div>
        </section>

        {/* footer */}
        <footer className="border-t border-gd-border py-12">
          <div className="flex flex-col items-start justify-between gap-4 sm:flex-row sm:items-center">
            <div className="flex items-center gap-2">
              <TerminalIcon size={16} className="text-gd-brand-mark" />
              <span className="text-body-sm text-gd-text-2">getdev</span>
            </div>
            <nav className="flex flex-wrap gap-x-6 gap-y-2 font-mono text-body-sm text-gd-text-3">
              <a href={REPO} {...ext} className="transition-colors hover:text-gd-text-1">
                github
              </a>
              <a href={RELEASES} {...ext} className="transition-colors hover:text-gd-text-1">
                releases
              </a>
              <a
                href={`${REPO}/blob/main/CONTRIBUTING.md`}
                {...ext}
                className="transition-colors hover:text-gd-text-1"
              >
                contributing
              </a>
              <a
                href={`${REPO}/blob/main/LICENSE`}
                {...ext}
                className="transition-colors hover:text-gd-text-1"
              >
                Apache-2.0
              </a>
            </nav>
          </div>
        </footer>
      </div>
    </div>
  )
}
