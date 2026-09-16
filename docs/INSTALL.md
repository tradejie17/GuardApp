# Installing Guard for Windows

There are two ways to run Guard, and the difference matters.

| | Developer setup | Deployed setup |
| --- | --- | --- |
| Extension loaded by | Developer mode, unpacked | Enterprise policy, force-installed |
| User can remove the extension | **Yes** | No |
| Suitable for | Building and testing | Actually restricting someone |

The developer setup is where you should start, and everything below builds on it. The deployed
setup adds the browser policy that makes the extension unremovable, and that step has real
prerequisites — signing and hosting — which are explained at the end.

---

## 1. Prerequisites

- Windows 10 or 11
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)
- [Node.js 18+](https://nodejs.org) (to build the extensions)
- An account with administrator rights

## 2. Install the service

From an **elevated** PowerShell prompt, in the repository root:

```powershell
.\scripts\install.ps1
```

This publishes the three executables to `C:\Program Files\Guard`, creates
`C:\ProgramData\Guard` and locks it to SYSTEM and Administrators, registers `GuardService` to
start automatically as `LocalSystem`, configures it to restart if it is killed, starts it, and
prompts you to set the administrator password.

**The password cannot be recovered.** If you lose it, the only way back is to delete
`C:\ProgramData\Guard\secrets\admin.json` as an administrator, which is exactly the bypass the
password exists to prevent — so treat losing it as needing a reinstall.

Check it worked:

```powershell
guardctl status
sc query GuardService
```

## 3. Build the extensions

```powershell
npm run build
```

This copies the shared detector and block page into each browser's folder and writes
`dist\chromium` and `dist\firefox`.

## 4. Load the extension (developer setup)

**Chrome, Edge, Avast Secure Browser**

1. Open `chrome://extensions` (or `edge://extensions`)
2. Turn on **Developer mode**
3. **Load unpacked** → select `dist\chromium`
4. Copy the 32-character extension id shown on the card

**Firefox**

1. Open `about:debugging#/runtime/this-firefox`
2. **Load Temporary Add-on** → select `dist\firefox\manifest.json`

A temporary add-on is removed when Firefox closes; that is a Firefox restriction on unsigned
add-ons, and the deployed setup below is how you get around it.

## 5. Connect the browser to the service

The browser will only launch the native host if it is registered in HKLM and the manifest names
your extension's id:

```powershell
.\scripts\register-native-host.ps1 -ChromeExtensionId <the id you copied>
```

Restart the browser. In the extension's service worker console you should see
`policy revision N applied`, and `guardctl status` will show the connection working when a
detection arrives.

## 6. Try it

```powershell
guardctl add-keyword "some-test-word"
```

Browse to `https://www.google.com/search?q=some-test-word`. The tab should land on the Guard
block page. Then:

```powershell
guardctl log
```

You should see one detection line, recording `https://www.google.com` — with no query string,
because full URLs are not stored by default.

---

## 7. Deployed setup: making the extension unremovable

A force-installed extension cannot be disabled or removed by the user; the Remove button
disappears and the toggle is gone. That is the property that turns this from "a tool you can
opt out of" into "a tool you have to know the password to opt out of".

Force-installing requires the browser to fetch the extension from an **update URL**. It will not
force-install a folder on disk. There are two routes:

### Chrome, Edge and Avast

**Route A — Chrome Web Store (recommended).** Publish the extension as **Unlisted**. It is not
searchable and only people with the link can see it, but the store hosts it and updates it. Then:

```powershell
.\scripts\configure-policies.ps1 -ChromeExtensionId <store id>
```

This route costs a one-time developer registration fee and the extension goes through review.

**Route B — self-hosted.** Pack a `.crx`, publish it and an update manifest XML on a URL the
machine can reach (an internal web server, or a local IIS site), then:

```powershell
.\scripts\configure-policies.ps1 -ChromeExtensionId <id> -UpdateUrl https://your-host/update.xml
```

Edge also accepts extensions from the Chrome Web Store, so route A covers Chrome, Edge and Avast
with one submission.

Add `-LockExtensionsPage` to also block `chrome://extensions` outright. It is effective, and it
blocks the page for every extension, not just Guard — decide whether that trade is right for you.

### Firefox

Firefox release builds refuse unsigned add-ons, with no policy to override it. You must get the
`.xpi` signed by Mozilla; **addons.mozilla.org offers signing for self-distribution**, which
gives you a signed file you host yourself without listing it publicly. Then:

```powershell
.\scripts\configure-policies.ps1 -ChromeExtensionId <id> -FirefoxXpiPath "C:\Program Files\Guard\guard.xpi"
```

This writes `policies.json` into Firefox's `distribution` folder. Add `-LockExtensionsPage` to
also set `BlockAboutAddons`.

### Confirming it took effect

Open `chrome://policy` (or `edge://policy`, `about:policies`) and reload policies. The extension
should be listed, and its card on the extensions page should read **Installed by enterprise
policy** with no Remove button.

---

## Uninstalling

```powershell
.\scripts\uninstall.ps1
```

Asks for the administrator password, then removes the service, the native host registration, the
browser policies and the program files. Add `-KeepData` to keep the policy and logs.

## Troubleshooting

**`guardctl` says it cannot reach the service.** `sc query GuardService`. If it is not running,
check `C:\ProgramData\Guard\logs\guard.log`.

**The extension never receives a policy.** The native host is not registered or the id is wrong.
Check `%LOCALAPPDATA%\Guard\nativehost.log` — it records connection failures — and confirm the
extension id in `C:\Program Files\Guard\native-hosts\com.guard.windows.chromium.json` matches
the one on the extension card.

**Detections are logged but nothing is blocked.** The policy is in log-only mode. Run
`guardctl set-action Block`.

**A keyword blocks more than intended.** Matching is substring-based, so `art` matches `cart`
and `article`. Use a longer keyword, or `guardctl allow-host` for a specific site.
