# Security model

Guard is a **self-control tool**. The person it restricts is usually the same person who
installed it and who holds the administrator account. That single fact shapes everything below:
the goal is not to defeat an attacker, it is to make the easy bypasses hard enough that acting
on an impulse takes a deliberate, slow decision instead.

Read every claim here as "resists a casual attempt", never "cannot be defeated".

## Trust boundaries

```
Browser extension       untrusted input      ─┐
  ↓ native messaging                          │  runs as the restricted user;
Guard.NativeHost        no privileges          │  can be inspected, modified, stopped
  ↓ named pipe                                ─┘
─────────────────────────────────────────────────────────────────
Guard.Service           trusted               ─┐  runs as LocalSystem;
  ↓                                            │  owns the policy, the password
Policy + password + logs                      ─┘  and the logs
```

Everything above the line runs as the restricted user and is assumed to be modifiable by them.
Everything below runs as `LocalSystem` and is protected by file ACLs and service permissions.

### What the service does not trust

The service receives detection reports from a process the restricted user controls, so it treats
every message as hostile input:

- **The reported keyword is re-verified.** The service runs its own matcher over the reported
  URL. If its policy does not produce the same match, the report is logged and discarded. A
  modified extension cannot manufacture detections for URLs that are not actually restricted.
- **The browser identity is validated** against a known set, so a report cannot claim to come
  from a browser that does not exist.
- **Stale and future timestamps are rejected** outside a ten-minute window, which stops a
  captured message from being replayed.
- **Message size is capped** at 64 KB per line on the pipe and 1 MB per native message, so a
  local process cannot exhaust the service's memory by sending an unbounded frame.
- **Connection count is capped** at 16 concurrent pipe clients.

### What the extension is trusted with

Blocking. The extension decides locally, from its cached policy, without asking the service.
This is a deliberate trade:

- **Gained:** blocking is instant with no IPC round trip in the navigation path, and it keeps
  working when the service is stopped or the machine is mid-boot. Stopping the service does not
  unblock browsing.
- **Given up:** someone who can modify the extension's files can stop it from blocking. The
  answer to that is the enterprise policy that force-installs it (see
  [INSTALL.md](INSTALL.md)), not a change to this design — because asking the service for
  permission on every navigation would not help either: the same person could still modify the
  extension to ignore the answer.

## The administrator password

The password is what stands between the restricted user and turning protection off. Any local
account can open the service pipe — it has to be reachable by the browser, which runs
unprivileged — so the password, not the pipe ACL, is the real gate.

- **PBKDF2-HMAC-SHA256, 600,000 iterations**, 16-byte random salt, 32-byte key, compared in
  constant time. Only the verifier is stored; the password itself is never written anywhere.
- **A floor on every attempt.** Verification always takes at least 750 ms whether it succeeds or
  fails, which caps the rate of scripted guessing and leaks nothing through timing.
- **Lockout after 5 failures** for 15 minutes, persisted to disk so restarting the service does
  not clear it.
- **`admin.json` is ACL'd to SYSTEM and Administrators**, with inheritance removed.

### What the password protects

| Action | Requires the password |
| --- | --- |
| Viewing protection status | No — deliberately |
| Adding or removing keywords and host rules | Yes |
| Changing the enforcement action | Yes |
| Pausing protection | Yes |
| Reading the detection log | Yes |
| Uninstalling through `uninstall.ps1` | Yes |
| Changing the password | Yes (or once, at first setup, when none exists) |

`status` is unauthenticated on purpose. Hiding whether protection is on produces confusion, not
safety, and the response contains no keywords and no log content.

### The bootstrap moment

Before any password is set, the first `password.set` is accepted without one — there is nothing
to authenticate against. `install.ps1` closes this window by prompting immediately after the
service starts. Until it is closed, every other administrative command is refused, and the event
is written to the audit log.

## Resistance measures, and their limits

| Measure | What it stops | What it does not stop |
| --- | --- | --- |
| Service runs as `LocalSystem`, files ACL'd to Administrators | Editing the policy or reading the password verifier as a standard user | An administrator taking ownership of the files |
| Service restarts on failure (`sc failure`, unlimited retries) | Killing the process from Task Manager | `sc stop` / `sc delete` from an elevated prompt |
| Extension enforces from its cached policy | Stopping the service to unblock browsing | Modifying the extension, if it is not force-installed |
| Extension force-installed by enterprise policy | Removing or disabling the extension from browser settings | Deleting the policy registry keys as an administrator |
| `-LockExtensionsPage` blocks `chrome://extensions` | Reaching the extension list at all | Launching the browser with `--disable-extensions` |
| Password gate on `uninstall.ps1` | Running the supported uninstaller | Deleting the files by hand as an administrator |
| Audit log of every administrative attempt | Quiet changes going unnoticed | An administrator deleting the log |

The pattern is consistent: each measure raises the cost of the easy path, and none of them
survives a determined administrator. **If you need a control that a user genuinely cannot
remove, the user must not be a local administrator** — run Guard on a machine where they hold a
standard account and someone else holds the administrator credentials. Everything in this
document gets considerably stronger under that assumption.

## Deliberate non-goals for v1

- **No page content inspection.** Guard reads URLs, never page text, which keeps the permission
  surface small and means the extension cannot see what you type into a page.
- **No network traffic.** No cloud, no account, no telemetry, no update check. Everything works
  offline, and there is no server to be breached or subpoenaed.
- **No options page in the extension.** There is nothing in the browser UI to switch off; every
  setting lives on the far side of the password.
- **No regular expressions in rules.** Literal substrings only, so a rule cannot be crafted into
  a runaway match, and what a rule does is obvious to whoever wrote it.
