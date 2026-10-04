# Platform Permission Guides — Pre-alpha

This document is the `platform_permission_guides` deliverable of M12. It
records, per platform, what permissions `OmniDesk` needs, which OS prompt
triggers them, and what the user is actually agreeing to.

Everything here is written against the current implementation. Where a
permission is *expected* by the design but not yet requested by the code, it
says so. A guide that describes intended behaviour as though it ships would be
worse than an incomplete one, because the first person to rely on it would be
a user discovering that a prompt never appeared.

## Why this document exists

A remote-desktop tool requests unusually broad access, and on every platform
some of that access is granted by a consent prompt that the user can
misread. Someone who clicks "Allow" on a screen-capture prompt has agreed to
something the prompt's wording does not explain.

The rule applied throughout: **the prompt text must describe the capability,
not the feature.** "Allow `OmniDesk` to capture this screen" is honest;
"Allow `OmniDesk` to connect" is not, because the user is agreeing to
sustained screen capture, not to a connection.

## Windows

### Current implementation

`omnidesk-core/src/windows_capture.rs` calls
`win_screenshot::capture_display()`. This is a **GDI `BitBlt` capture**. No
consent prompt appears; Windows does not impose one for GDI screen capture of
the primary display.

That is the uncomfortable fact this section exists to state plainly: **on the
current build, OmniDesk captures the screen with no OS prompt at all.** The
user sees nothing. Nothing in the OS tells them capture is happening.

GDI capture is also visible in two ways a user can check, and the product
should not pretend otherwise:

- A screen-capture indicator appears in the taskbar or notification area,
  depending on Windows version.
- The cursor is typically **not** captured, and hardware overlays are not
  rendered, because they are not in the desktop's device-independent bitmap.

| Permission | Trigger | Prompt | Notes |
|---|---|---|---|
| Screen capture (primary display) | Automatic on capture | **None** | GDI `BitBlt`. Not user-visible |
| Input injection | Automatic | **None** | Not implemented in this repo |
| Filesystem access | On file transfer | **None** | Path-sanitised; see below |
| Clipboard | On sync | **None** | `ClipboardSyncState` stores only a digest |

### What changes before release

| Change | Why |
|---|---|
| Move to Windows.Graphics.Capture | The OS draws a consent banner naming the app. Capture becomes visible and revocable |
| Per-monitor capture | Needed for M8 `multi_monitor`. WGC supports it; GDI `BitBlt` does not |
| Protected-content handling | WGC can exclude DRM surfaces. Silent black regions otherwise look like a bug |

Moving to WGC is the single highest-value permission change on any platform:
it converts an invisible capability into a visible, user-controlled one, and
it is a security improvement rather than a feature.

### Known gap

The sandbox elevation prompt, if capture is ever implemented in a sandboxed
context, is not documented here because it is not reachable in this repo.

## macOS

### Current implementation

**Nothing.** There is no macOS capture path in this repository. Everything in
this section is a requirement for the future implementation, not a description
of current behaviour.

### Requirements for the future implementation

| Permission | Mechanism | Prompt | Notes |
|---|---|---|---|
| Screen recording | `CGPreflightScreenCaptureAccess` / `CGRequestScreenCaptureAccess` | **Yes**, system dialog | Denied state must be distinguishable from failure |
| Accessibility | `AXIsProcessTrusted` / `AXIsProcessTrustedWithOptions` | **Yes**, system dialog | Required for input synthesis |
| Input monitoring | `IOHIDRequestAccess` | **Yes**, system dialog | Required for pointer capture |
| Microphone | `AVCaptureDevice.requestAccess` | **Yes**, system dialog | Only for `remote_audio` |
| Files and folders | User-selected only, via powerbox | Per file | No arbitrary path access |
| Keychain | `SecItem` | Per item | Entitlements only |

### Deny handling, which is the part that gets skipped

macOS permits the user to deny any of these, and the denial is permanent
until changed in System Settings — there is no in-app prompt to retry.

Three states must be distinguished and none of them may be collapsed:

1. **Not yet requested** — prompt the user, explaining why.
2. **Denied** — the user said no. Do not re-prompt on launch. Direct to System
   Settings with the exact pane. Re-prompting after an explicit denial is the
   behaviour macOS users report as harassment, and it trains them to click
   through dialogs without reading them.
3. **Restricted by policy** — an MDM profile forbids it. This is not a user
   decision and must not be presented as one.

Collapsing (2) into (1) causes a prompt loop. Collapsing (3) into (2) tells a
user they can fix something by changing a setting when they cannot.

`Screen Recording` must be requested *after* the user starts a session, not at
launch. A permission prompt during startup, before the user has any context for
what the app does, is the worst possible time to ask for screen recording.

## Linux

### Current implementation

**Nothing.** There is no Linux capture path. This section states requirements.

The critical property: **Linux has no single portable screen-capture
mechanism, and OmniDesk must not silently degrade to one that captures more
than the user agreed to.**

| Backend | Mechanism | Consent | Notes |
|---|---|---|---|
| PipeWire | `xdg-desktop-portal` `ScreenCast` | **Yes**, portal dialog | The only portable, consent-correct path |
| X11 | `XGetImage` on the root window | **None** | Silent full-screen capture. Not acceptable |
| X11 (window) | `XGetImage` on a window | **None** | Silent capture of one window |

`XGetImage` is the same class of problem as Windows GDI capture: it works,
it is silent, and it captures without the user knowing. If a future Linux
build uses it, it must at minimum surface the capture to the user itself,
because the OS will not.

Portal-based capture must request `Interactive` or `Non-Destructive` selection
and must not assume a single monitor: the portal returns a list, and picking
the first entry silently drops the user's other displays.

Wayland sessions may additionally restrict portals via a lockdown
configuration. That must surface as the "restricted by policy" case above, not
as a generic failure.

## Android and iOS

Listed as `later` in `ROADMAP.yaml`. Not implemented. Recorded so the
requirement is not discovered late:

- **Android** requires `MediaProjection` consent *per session*, obtained
  through `MediaProjectionManager.createScreenCaptureIntent()`. The user sees a
  system dialog on every cast. `FOREGROUND_SERVICE_MEDIA_PROJECTION` is
  required to keep capture alive in the background.
- **iOS** requires `NSScreenCaptureUsageDescription`, and for the
  broadcast-extension model requires a `ReplayKit` extension, which captures
  via a separate process with its own memory limits.

Both platforms also require explicit foreground-service or background-task
declarations; capture cannot continue in the background without them.

## Cross-platform rules

These hold regardless of platform and are the part most likely to be violated
by a convenient implementation:

1. **Request the narrowest scope that works.** One display, not all displays.
   One window, not the whole screen. Clipboard one direction at a time.
2. **Request at the moment of use,** never at launch or first run.
3. **Never re-prompt after an explicit denial.** Direct to settings.
4. **Distinguish denied from restricted from unavailable.** They need different
   responses and different text.
5. **State the capability, not the feature,** in every prompt.
6. **Degrade by reducing scope, not by capturing anyway.** No capture at all is
   the correct answer when consent is absent.
7. **The permission state is visible in the product,** not only in the OS.
   `clear_security_state` from M7's `ux_rules` applies here: a user must be
   able to see what the app currently has access to and revoke it.

## Unverifiable claims

Stated explicitly, per this repository's rule against unverified assertions:

- **No prompt in this guide has been observed firing.** The current
  implementation has one capture path, on Windows, and it produces no prompt.
  The macOS, Linux, Android, and iOS rows describe documented OS behaviour for
  an implementation that does not exist here.
- **No consent state has been tested.** There is no code that requests,
  detects, or handles a permission grant or denial on any platform.
- **M12's `permission_guides` deliverable is not complete** on this basis. What
  exists is the requirement set and the decisions above. Confirming them
  against running builds on each platform is the remaining work, and it needs
  the hardware.