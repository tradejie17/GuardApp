# Guard for Windows

Cross-browser keyword monitoring and self-control system.

Guard watches browser navigation across Chrome, Edge, Firefox and Avast Secure Browser, detects
configured keywords anywhere in a URL, and blocks the navigation. The rules, the password and
the logs live in a Windows service running as `LocalSystem`, so turning protection off takes the
administrator password rather than a click in browser settings.

This is **v1**. It implements detection, blocking and password-protected administration. The
more aggressive enforcement actions from the design (closing the browser, locking the session,
shutting down) are defined in the configuration schema but are not implemented yet; a policy
that asks for one of them blocks the navigation instead, and says so.

---

## How it works

```
┌──────────────────────────────────────────────────────────────┐
│  Chrome │ Edge │ Avast  ──► Chromium extension (Manifest V3) │
│  Firefox               ──► Firefox extension (WebExtension)  │
│                                                              │
│  Detects the keyword locally and stops the navigation        │
└───────────────────────────┬──────────────────────────────────┘
                            │ native messaging (stdio, JSON)
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  Guard.NativeHost — runs as the user, translates framing     │
│  No policy, no decisions, no privileges                      │
└───────────────────────────┬──────────────────────────────────┘
                            │ named pipe (newline-delimited JSON)
                            ▼
┌──────────────────────────────────────────────────────────────┐
│  Guard.Service — runs as LocalSystem                         │
│                                                              │
│  Owns the policy, the password and the logs                  │
│  Re-verifies every reported detection against its own rules  │
│  Pushes policy changes to every connected browser instantly  │
└──────────────────────────────────────────────────────────────┘
                            ▲
                            │ named pipe
                    guardctl (administration)
```

Two design decisions are worth calling out, because they are what make the system behave well
in practice:

**The extension decides, the service records.** The extension holds a cached copy of the policy
and blocks synchronously, without asking the service first. Blocking is therefore instant, and
it keeps working if the service is stopped — killing the service is not a way to unblock
browsing. The service re-runs the same rules over every report it receives, so a detection it
cannot reproduce is logged and discarded rather than acted on.

**One detection engine, two implementations.** `Guard.Core.Detection` (C#) and
`guard-detect.js` (JavaScript) are deliberate mirrors of each other, and
[the same test cases](tests/Guard.Core.Tests/KeywordMatcherTests.cs) run against
[both](src/extension-shared/guard-detect.test.mjs) so they cannot drift.

## What counts as a match

Matching is literal substring matching against a normalized URL — no regular expressions, so a
keyword behaves the way the person who typed it expects and a crafted URL cannot cause a
runaway match.

Before matching, a URL is decoded (repeatedly, to catch double-encoding), `+` is treated as a
space, compatibility Unicode is folded onto ASCII, and the result is lowercased. So the keyword
`keyword` matches all of these:

```
https://google.com/search?q=keyword
https://google.com/search?q=hello+keyword
https://google.com/search?q=hello%20keyword
https://google.com/search?q=hello%2520keyword
https://example.com/article/keyword/test
https://example.com/page#keyword
https://example.com/ｋｅｙｗｏｒｄ
```

Host rules cover subdomains (`example.com` also blocks `www.example.com` but not
`notexample.com`), and the allowlist is checked first, so an exempt site stays reachable even
when its URL contains a restricted keyword.

## Quick start

Requires Windows 10/11, an elevated PowerShell prompt, and the [.NET 8 SDK](https://dotnet.microsoft.com/download).

```powershell
git clone <this repository>
cd Guard-Windows

# 1. Build and install the service, native host and guardctl. Prompts for the admin password.
.\scripts\install.ps1

# 2. Build the extensions
npm run build          # writes dist\chromium and dist\firefox

# 3. Load dist\chromium in chrome://extensions (Developer mode), note the extension id,
#    then wire the browser to the service:
.\scripts\register-native-host.ps1 -ChromeExtensionId <the 32-character id>

# 4. Add a rule and check it works
guardctl add-keyword "some-test-word"
guardctl status
```

Browse to a URL containing the keyword: the tab lands on the Guard block page, and
`guardctl log` shows the detection.

For deployment — force-installing the extension so it cannot be removed, and the signing
requirements that come with that — see **[docs/INSTALL.md](docs/INSTALL.md)**.

## Administration

Every command except `status` requires the administrator password. `status` deliberately does
not, so a restricted user can see that protection is on without being able to change it.

```
guardctl status                          Protection state, rule counts, log location
guardctl list                            Keywords and host rules
guardctl add-keyword "restricted phrase" Add a keyword (quotes only needed for clarity)
guardctl remove-keyword "phrase"         Remove one
guardctl block-host example.com          Block a site and its subdomains
guardctl allow-host docs.example.com     Exempt a site from every rule
guardctl set-action LogOnly|Block        Observe only, or block
guardctl pause --minutes 30 --reason ""  Temporarily suspend protection (max 8 hours)
guardctl resume                          Resume immediately
guardctl log --count 50                  Recent detections
guardctl set-password                    Change the administrator password
```

Changes take effect immediately: the service pushes the new policy to every connected browser,
with no restart needed.

Run `set-action LogOnly` first when introducing a new keyword. It records what *would* have been
blocked without interrupting anything, which is the cheapest way to find a keyword that matches
more than you intended.

## Repository layout

```
src/Guard.Core/            Detection engine, config models, IPC contracts, password hashing
src/Guard.Service/         Windows service: pipe server, policy, enforcement, logging
src/Guard.NativeHost/      stdio ⇄ named pipe bridge launched by the browser
src/Guard.Cli/             guardctl
src/extension-shared/      Detector, service link and block page shared by both extensions
src/Guard.Chromium/        Manifest V3 extension (Chrome, Edge, Avast)
src/Guard.Firefox/         WebExtension (Firefox)
tests/Guard.Core.Tests/    xUnit tests for the C# engine
scripts/                   install, uninstall, native host registration, browser policies
config/guard.sample.json   An annotated example policy
docs/                      Install guide, security model, testing notes
```

## Tests

```bash
dotnet test     # 43 tests: URL normalization, keyword matching, password hashing
npm test        # 36 tests: the JS detector, plus both background scripts against a stubbed
                #           browser API (block, allow, log-only, pause, rule generation)
```

Everything platform independent is covered automatically and runs on any OS. Windows-specific
behaviour — ACLs, the Service Control Manager, pipe security, browser policy — has to be checked
on a Windows machine; [docs/TESTING.md](docs/TESTING.md) is the checklist.

## Limits worth knowing

Guard is a **hardening mechanism, not a security boundary**. It is built for someone who wants
to make a habit harder to act on, and the honest description of what it resists is "the
impulsive attempt", not "a determined attacker with administrator rights on their own machine".

- A local administrator can always remove a service from their own computer. The password gate
  on `uninstall.ps1` is an obstacle, not a lock.
- Detection is URL-based. It does not read page content, so a restricted topic reached without
  the keyword appearing in the URL is not detected.
- Blocking depends on the extension being installed. Force-installing it by enterprise policy
  is what stops a user from simply removing it — see [docs/INSTALL.md](docs/INSTALL.md).
- A browser Guard has no extension for, and private/incognito windows where the extension is not
  enabled, are not covered.

See [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) for the full picture, including what each
component is trusted with and why.

## Privacy

Detections are recorded, browsing is not. A log line holds the timestamp, the browser, the
matched keyword and the scheme plus host — never the query string, which is where the search
terms are. Setting `logging.storeFullUrl` to `true` opts into recording complete URLs; it is off
by default. Nothing is ever sent off the machine: there is no cloud, no account and no network
call anywhere in the system.

## Roadmap

| Version | Adds |
| --- | --- |
| **v1** *(this release)* | Keyword and host rules, all four browsers, blocking, logging, password-protected administration |
| v1.5 | `CLOSE_BROWSER` and `LOCK_WINDOWS` enforcement, scheduled rules |
| v2.0 | `SHUTDOWN` with countdown and cancellation, signed installer (MSI) |
| v2.5 | WinUI 3 administration GUI, statistics, detection history |
