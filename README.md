# ARIA — Automotive LLM Security CTF

A self-contained "capture the flag" chatbot built for security training /
conference booths (e.g. DEF CON AI Village). Players talk to **ARIA**, the
in-vehicle assistant for a fictional car company, "Nexus Motors," and try to
recover three flags, each mapped to an OWASP LLM Top-10 style vulnerability:

| Objective | Vulnerability class          | Flag                                               |
|-----------|-------------------------------|-----------------------------------------------------|
| OBJ.01    | Prompt Injection (Direct & Indirect) | `flag{pr0mpt_1nj3ct10n_hij4cks_th3_wh33l}` |
| OBJ.02    | Insecure Output Handling       | `flag{1nsecur3_0utput_cr4shes_th3_d0m}`             |
| OBJ.03    | Sensitive Information Exfiltration | `flag{s3ns1t1v3_d4t4_le4ks_p4st_th3_f1lt3r}`   |

**Important:** these flags are the defaults baked into this copy of the code.
Before running this at a real event, change them (see "Customizing flags"
below) so they aren't guessable from this public writeup.

All vulnerable logic and the flag values live server-side in `/api`
(Vercel Serverless Functions), never in the files served to the browser.
Players can't just "view source" to get the flags — they have to actually
exploit the bugs.

## How it's structured

```
nexus-ai-ctf/
├── index.html        # static frontend — chat UI
├── style.css          # automotive HUD styling
├── app.js             # client logic — INTENTIONALLY renders bot replies
│                       # with innerHTML instead of textContent (OBJ.02)
├── api/
│   ├── chat.js         # ARIA's "brain" — system prompt, injection
│   │                    # detection, sensitive-data filter (and its bypasses)
│   └── session.js       # sets a non-HttpOnly cookie holding FLAG2 (base64) —
│                         # the sink an XSS payload is meant to reach
├── package.json
└── vercel.json
```

Nothing here calls a real LLM API — the "chatbot" is a small rule-based
simulation, so there's no API key to manage and no per-message cost. That
keeps hosting free and the challenge deterministic and reliable for a booth
with lots of concurrent players.

## Deploying to Vercel (free tier)

### Option A — Vercel CLI (fastest)

1. Install Node.js if you don't have it (v18+).
2. Install the Vercel CLI:
   ```bash
   npm install -g vercel
   ```
3. From inside the `nexus-ai-ctf` folder:
   ```bash
   cd nexus-ai-ctf
   vercel
   ```
4. Follow the prompts:
   - "Set up and deploy?" → **Y**
   - Log in / create a free Vercel account if prompted (GitHub, GitLab, email, etc.)
   - "Link to existing project?" → **N**
   - Project name → anything, e.g. `aria-ctf`
   - Directory → `.` (current directory)
   - Override settings? → **N** (defaults are correct — no build step needed)
5. Vercel deploys and gives you a URL like `https://aria-ctf.vercel.app`.
6. For a permanent production URL (not a preview URL), run:
   ```bash
   vercel --prod
   ```

That's it — the `/api` folder is auto-detected as serverless functions, and
the root files (`index.html`, `style.css`, `app.js`) are served as static
assets. No build command, no environment variables required.

### Option B — GitHub + Vercel dashboard (no CLI)

1. Push this folder to a new GitHub repository.
2. Go to https://vercel.com → **Add New → Project**.
3. Import the GitHub repo.
4. Framework preset: **Other**. Leave build command and output directory
   blank/default.
5. Click **Deploy**.

### Option C — Other free platforms

- **Netlify**: works the same way, but Netlify's equivalent of `/api` is
  `/netlify/functions`. You'd move `api/chat.js` and `api/session.js` into
  that folder and adjust the fetch paths in `app.js` from `/api/chat` to
  `/.netlify/functions/chat` (and same for `session`). Netlify's free tier
  also supports this at no cost.
- **Cloudflare Pages + Pages Functions**: similar idea — functions live in
  a `/functions` directory using a slightly different handler signature
  (`onRequestPost`). Would need a small rewrite of the two API files.
- **GitHub Pages**: static-only, no serverless functions — would only work
  if you convert the two vulnerabilities that need a backend into pure
  client-side logic, which reintroduces the "flags visible in view-source"
  problem this design avoids. Not recommended for this challenge.

Vercel is the easiest match for this project as-is because it needs zero
configuration for both the static frontend and the two serverless functions.

## Running it locally before deploying

```bash
npm install -g vercel
cd nexus-ai-ctf
vercel dev
```

This runs the exact same static + serverless-function setup on
`http://localhost:3000`.

## Customizing flags for a real event

Change the flag constants in:
- `api/chat.js` → `FLAG1`, and `VEHICLE_RECORD.diagnosticKey` (FLAG3)
- `api/session.js` → `FLAG2`

Then regenerate the SHA-256 hashes used by the client-side "flag tracker"
(a cosmetic progress checklist — not a security boundary, just UX) in
`app.js` (`FLAG_HASHES`):

```bash
node -e "
const crypto = require('crypto');
console.log(crypto.createHash('sha256').update('flag{your-new-flag}').digest('hex'));
"
```

Paste the resulting hex string into `FLAG_HASHES` in `app.js` for the
matching objective number.

## Player-facing challenge brief

See the in-app "Challenge Briefing" modal (top-right button) for the
player-facing hint text. For a deeper solutions/answer-key writeup for
organizers and proctors, see `SOLUTIONS.md` in this folder — **don't**
publish that file alongside a live deployment.
