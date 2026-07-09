# Threat Model — Starlight Cipher Suite

This document covers the parts of the app where getting the security model wrong has real
consequences: **The Basementen** vault (master password, generated keys, encrypted
transaction history) and how the app is packaged and distributed. The other ten ciphers
(Caesar, Vigenère, Rail Fence, etc.) are educational/puzzle tools with no confidentiality
goal — their "security" is not in scope.

## System overview

Starlight Cipher Suite is a client-side-only application with no backend and no network
calls at runtime. It ships in three forms:

- **Static web page** — `index.html` + vendored JS/CSS, opened directly or served by any
  static file host.
- **Installable PWA** — `manifest.json` only; there is no service worker, so there is no
  offline cache and no update-checking logic to attack.
- **Desktop app** — `launcher.py` (packaged with PyInstaller) starts a plain
  `http.server` bound to `127.0.0.1` and points a `pywebview` window at it. The
  executable is signed with a self-signed code-signing certificate
  (`StarlightRoot.cer`); `sign_app.ps1` shows how that certificate and its private key
  are generated (the private key never leaves the developer's certificate store and is
  not in this repo).

All persistent state — cipher preferences, plaintext history for the toy ciphers, and the
Basementen vault — lives in the browser's/webview's `localStorage`. There is no server-side
component that ever sees a password or plaintext.

## Assets

| Asset | Where it lives | Sensitivity |
|---|---|---|
| Basementen master password | Never stored — typed each session | Highest: gates everything below |
| Generated 256-bit vault key (`basementenKey`) | In memory only while unlocked; encrypted at rest in `localStorage['basementen_encrypted_key']` | High |
| Per-transaction passwords | Never stored — typed per save/reveal | High |
| Encrypted transaction history (`basementen_history`) | `localStorage`, one AES-GCM blob per entry | High |
| Plaintext/ciphertext currently in the compose boxes | DOM only, while the vault is unlocked | High while present |
| OS clipboard contents | OS-level, outside the app's control | High if it contains revealed plaintext |
| General (non-vault) cipher history | `localStorage['cipher_craft_history']`, **plaintext by design** | Low — these ciphers make no confidentiality claim |
| Code-signing private key | Developer's Windows certificate store, outside this repo | High, but out of this app's runtime scope |

## Trust boundaries

```
[ Attacker on the network ]
        |  (no requests are ever made — nothing to intercept)
        v
[ Static host / filesystem ]  --serves-->  [ Browser or WebView2 tab ]
                                                  |
                                      localStorage (per-origin)
                                                  |
                                      In-page JS: app.js, ciphers.js,
                                      argon2.min.js (vendored, no CDN)

Desktop only:
[ Other local process on the same machine ] --http://127.0.0.1:PORT--> [ launcher.py's static server ]
```

The main trust boundary is the browser/WebView2 origin: everything inside it (any script
that executes there, whether it's `app.js` or an injected one) has equal access to
`localStorage` and the DOM. There is no privilege separation inside the page.

## Adversaries considered

- **Someone with the stored vault data but not the password** (a copy of `localStorage`,
  a stolen device, a synced browser profile) — the primary adversary this app defends
  against.
- **Someone with unattended, momentary access to an already-unlocked session** (walked
  away from the machine, tab left open) — addressed by auto-lock.
- **A malicious/compromised browser extension, or a future XSS bug in this app** — has
  full access to the page's `localStorage` and DOM. It could read ciphertext or capture a
  password as it's typed; it cannot brute-force the Argon2id-derived key any faster than
  described below.
- **Another local process/user on the same machine as the desktop build**, hitting its
  loopback HTTP server.
- **A future contributor** who accidentally weakens a security-relevant constant (KDF
  iterations/memory, missing a `kdf` tag, reintroducing raw `innerHTML`).

## Adversaries explicitly *not* defended against

- **Malware with full control of the OS/browser process the app is running in**
  (keyloggers, memory scrapers, root-level access). If the machine is owned, no
  client-side app can protect what's typed into it.
- **A remote network attacker**, beyond the general expectation that if this is ever
  self-hosted over plain HTTP rather than HTTPS, a network MITM could serve modified
  JS. (Nothing in the app calls out over the network at runtime, so there's no live
  traffic to intercept once loaded — but the initial page load itself is only as
  trustworthy as its transport and host.)
- **Legal/coercive disclosure of the master password** (rubber-hose cryptanalysis) —
  out of scope for any password-based scheme.

## Threats and mitigations

### Vault key derivation & storage

| Threat | Mitigation | Where |
|---|---|---|
| Offline brute-force of a stolen `localStorage` blob | Argon2id (19 MiB, t=2) for all new master/transaction passwords; makes GPU/ASIC parallelism expensive | `app.js` `deriveKeyArgon2id` |
| Ciphertext/plaintext recovery without the key | AES-256-GCM (authenticated encryption — tampering is detected, not silently decrypted) | `app.js` `deriveKeyArgon2id`, `deriveKeyLegacyPBKDF2` |
| Rainbow-table / precomputation attacks | Fresh random salt (16 bytes) per master key and per transaction | every `crypto.getRandomValues(new Uint8Array(16))` call site |
| IV reuse breaking GCM's confidentiality guarantee | Fresh random IV (12 bytes) per encryption operation | same call sites |
| A future change silently weakening the KDF | Regression test asserting Argon2id memory/hash-length and the legacy PBKDF2 floor | `tests/security/vault-security.test.mjs` |
| Corrupted/tampered stored ciphertext bricking the vault or crashing the app | GCM auth failure is caught and surfaced as "Incorrect password" instead of throwing | `showBasementenUnlock` catch block; tested |

### Vault session lifecycle

| Threat | Mitigation | Where |
|---|---|---|
| Decrypted key/plaintext left in memory indefinitely | `lockBasementen()` is the single lock path for click-away, idle timeout, tab-hidden, and wipe; clears every in-memory secret | `app.js` |
| Walking away from an unlocked, unattended session | 5-minute inactivity auto-lock | `startBasementenIdleWatcher` |
| Backgrounding the tab while unlocked | Immediate lock on `visibilitychange` | `startBasementenIdleWatcher` |
| Plaintext/ciphertext lingering in the compose boxes after a lock | Cleared as part of `lockBasementen()` | `app.js` |
| Transaction password accidentally reusing the master password | Checked and rejected before saving | `isMasterPassword` |

### Rendering / injection

| Threat | Mitigation | Where |
|---|---|---|
| Stored XSS via a transaction name or history entry rendered back into the DOM | User-controlled fields are set via `textContent`/`createTextNode` or passed through `escapeHtml()` before any `innerHTML` use | `renderHistory`, `renderBasementenLog`, tested |

### Distribution & supply chain

| Threat | Mitigation | Where |
|---|---|---|
| A CDN or npm dependency being compromised or going offline | All third-party code (`lucide.min.js`, `qrcode.js`, `argon2.min.js`) is vendored into the repo; nothing is fetched at runtime | `index.html` |
| Tampered/unrecognized desktop executable | Authenticode-signed with a project-specific certificate; users can optionally trust the signer | `sign_app.ps1`, `launcher.py` |
| Over-broad trust from installing the signing cert | The trust prompt is opt-in, shown at most once, explained in plain language, and only installs to the *current user's* store (not machine-wide) | `launcher.py: offer_certificate_trust` |

## Known limitations / accepted risks

These are conscious tradeoffs, not oversights — noted here so they're a decision rather
than a surprise later.

- **The Basementen's message cipher provides no confidentiality on its own.** It's a
  repeating-key substitution over a 92-character alphabet (`ciphers.js: Basementen`) —
  trivially breakable with frequency analysis if the key were ever exposed. All real
  protection comes from the master-password-gated AES-256-GCM storage layer, not from
  this cipher. This should stay explicit in any user-facing copy.
- **No brute-force rate limiting on the unlock form.** There's no server to enforce
  lockouts, and a client-side counter is trivially bypassed by anyone who can already read
  `localStorage`. Argon2id's cost-per-guess is the only throttle. This is standard for a
  fully client-side, no-backend design and is not considered fixable without adding a
  server (which would be a much bigger architectural change).
- **Old transaction history entries don't get auto-upgraded to Argon2id.** Only the
  single master key is migrated on next unlock; per-transaction entries created before
  this change keep their original `kdf` tag and stay on legacy PBKDF2 indefinitely (still
  a real KDF, just a weaker one). Re-saving a transaction is the only way to upgrade it.
- **Revealed plaintext can be copied to the OS clipboard** (`app.js`, several
  `navigator.clipboard.writeText` call sites). The clipboard is shared, unencrypted OS
  state that other apps (including clipboard-history managers) can read and that this app
  has no control over once the copy happens.
- **No password strength enforcement beyond a 10-character minimum and an advisory
  strength meter.** A weak-but-long-enough password is a weak link Argon2id's cost factor
  cannot fully compensate for.
- **`README.md` says "open `index.html` directly" works, but in current Chromium it
  doesn't** — `app.js` is loaded as an ES module and importing `ciphers.js` over
  `file://` is blocked by CORS. This is a functionality bug that happens to shape the
  security picture too: it nudges anyone hosting this themselves toward "serve it over
  HTTP(S)," at which point *how* they serve it (plain HTTP vs. HTTPS, who else can
  reach that host) matters more than anything client-side. Not fixed as part of this
  work; flagged here since it affects real deployment assumptions.
- **The desktop app's loopback HTTP server has no authentication.** Any other process
  running as the same OS user can request `http://127.0.0.1:<port>` and receive the
  static app files. Since the server only ever serves static assets (no endpoints with
  side effects or access to `localStorage`, which is scoped to the WebView2 profile, not
  the HTTP server), the practical impact is limited — but it's a real, non-zero local
  attack surface worth knowing about.

## Suggested follow-ups (not yet implemented)

Roughly in order of value for effort:

1. Auto-clear the clipboard a short time after copying revealed vault plaintext.
2. Offer an explicit "re-encrypt this entry" action in the transaction log so users can
   opt individual old entries into Argon2id without re-typing the whole transaction.
3. Fix the `file://` ES-module loading issue (either drop the module/`import` split for
   `app.js`/`ciphers.js`, or update the README to stop recommending direct `file://` use).
4. If this is ever self-hosted rather than run locally, serve it over HTTPS and consider
   a restrictive Content-Security-Policy — cheap insurance against a future XSS bug given
   how much this app keeps in `localStorage`.
