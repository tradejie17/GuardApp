# Testing

## Automated

```bash
dotnet test     # 43 tests — the C# detection engine and password hashing
npm test        # 36 tests — the JS detector and both background scripts
```

Both suites run on any operating system and in CI, because everything they cover is platform
independent.

**`tests/Guard.Core.Tests`** covers URL normalization (component splitting, percent-decoding,
double-encoding, `+` as space, full-width Unicode, malformed escapes, oversized input), keyword
matching (every part of the URL, case sensitivity, disabled component checks, host rules and
subdomains, allowlist precedence, internal browser schemes, duplicate and blank keywords) and
password hashing (verification, per-hash salting, blank rejection, corrupted stored values).

**`src/extension-shared/guard-detect.test.mjs`** is the same list of cases against the
JavaScript engine. The two files are meant to be read side by side: if you change matching
behaviour in one engine and not the other, one of these suites should fail.

**`src/extension-shared/background-smoke.test.mjs`** loads `Guard.Chromium/background.js` and
`Guard.Firefox/background.js` in a VM with a stubbed WebExtension API and drives real decisions
through them — a restricted navigation is redirected to the block page and reported, an
unrelated one is untouched, sub-frames are ignored, log-only reports without blocking, a pause
suspends blocking, and the generated declarativeNetRequest rules have allow rules outranking
block rules with unexpressable keywords left to the detector.

## Manual, on Windows

These cannot be automated here; they are the checklist to run on the target machine after
`install.ps1`.

### Service and permissions

- [ ] `sc query GuardService` shows `RUNNING`, start type `AUTO_START`
- [ ] The service survives a reboot
- [ ] Killing `Guard.Service.exe` from Task Manager: it restarts within ~5 seconds
- [ ] As a **standard** user, `notepad C:\ProgramData\Guard\config\guard.json` is denied
- [ ] As a **standard** user, `C:\ProgramData\Guard\secrets\admin.json` is not readable
- [ ] As a **standard** user, `guardctl status` still works

### Password

- [ ] A wrong password is refused, and each attempt visibly takes about a second
- [ ] Five wrong attempts lock out the sixth, including with the correct password
- [ ] The lockout survives `Restart-Service GuardService`
- [ ] `guardctl set-password` requires the current password once one is set
- [ ] Every attempt appears in `C:\ProgramData\Guard\logs\audit.log`

### Detection, per browser (Chrome, Edge, Firefox, Avast)

- [ ] `?q=keyword` is blocked
- [ ] `?q=hello+keyword` and `?q=hello%20keyword` are blocked
- [ ] `KEYWORD` in upper case is blocked
- [ ] The keyword in the path and in the fragment is blocked
- [ ] A blocked host and one of its subdomains are blocked
- [ ] An allowlisted host is reachable even with a keyword in the URL
- [ ] An unrelated search is not blocked
- [ ] The block page renders correctly in both light and dark mode
- [ ] A single-page app that changes the URL without a page load is caught

### Policy propagation

- [ ] `guardctl add-keyword` takes effect in an already-open browser with no restart
- [ ] `guardctl pause --minutes 1` stops blocking, and it resumes by itself after a minute
- [ ] `guardctl set-action LogOnly` records without blocking

### Failure modes

- [ ] `Stop-Service GuardService` — the browser **keeps blocking** from its cached policy
- [ ] Restarting the service: the extension reconnects within about a minute
- [ ] Corrupting `guard.json` by hand: the service keeps the previous policy and logs the error
- [ ] Deleting `guard.json`: defaults are written, protection stays on
- [ ] A browser started before the service: the extension connects once the service is up

### Hardening (deployed setup)

- [ ] The extension shows **Installed by enterprise policy** and has no Remove button
- [ ] The extension cannot be disabled from the extensions page
- [ ] With `-LockExtensionsPage`, `chrome://extensions` does not open
- [ ] `uninstall.ps1` refuses to proceed without the password

## Logs to check when something is wrong

| File | What it holds |
| --- | --- |
| `C:\ProgramData\Guard\logs\guard.log` | Service lifecycle, connections, errors |
| `C:\ProgramData\Guard\logs\detections.log` | One line per confirmed detection |
| `C:\ProgramData\Guard\logs\audit.log` | Every administrative attempt, allowed or refused |
| `%LOCALAPPDATA%\Guard\nativehost.log` | Native host connection failures (written as the user) |
| The extension's service worker console | Policy revisions applied, rule counts |
