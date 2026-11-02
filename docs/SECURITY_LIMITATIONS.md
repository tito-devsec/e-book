# Security limitations

The platform makes casual sharing of a purchased book hard and makes misuse visible to the owner.
It does **not** make copying impossible, and nothing that shows a book in a web browser can. This
document says exactly what is and isn't protected, so nobody promises customers or the owner
more than is true.

## What is protected

| Goal | How | Strength |
|---|---|---|
| Nobody gets the original EPUB/PDF | Original encrypted in private storage; never served to any browser, including the buyer's | Strong |
| Only paying customers can read | Payment verification by the owner, license checks on every request | Strong |
| A link can't be used twice | The link is used up the first time the added app opens; after that it only shows "already used" | Strong. Before the book is added, whoever holds the link can add it: the link is the proof of purchase, so it should go only to the buyer. The owner sees every device and can revoke it and send a new link |
| A shared reader URL shows nothing | Every content request needs session + registered device key + license | Strong |
| A stolen session cookie doesn't work alone | Requests must be signed with the browser's non-extractable device key | Good against cookie theft; not against malware controlling the browser |
| Access can be withdrawn | Revocation, suspension and device removal take effect on the next request | Strong for future reading; see below for what was already seen |
| One purchase, one device | Device limit per license, controlled device moves, alerts | Moderate (see "Device identity") |

## PDF books: layers of protection

| Layer | What it does | What it stops |
|---|---|---|
| Encrypted original | The PDF is encrypted (AES-256-GCM, per-edition key wrapped by KMS) the moment it is uploaded and is never written to disk in clear | Theft of the server's files or bucket |
| Server-side rendering | pdf.js turns each page into an image on the server; no PDF bytes ever reach a browser | "Save as PDF", PDF downloaders, extracting the file from the app |
| One page per request | Each page is requested separately with a signed, session-bound, rate-limited request | Bulk download scripts, replaying requests, shared links |
| Burned-in watermark | Every page image is stamped, per request, with the buyer's name, masked number, date and a trace ref | Anonymous leaks: any screenshot, photo or printout identifies the buyer; the dashboard finds them by ref |
| Canvas display | Pages are drawn on a `<canvas>` from in-memory bitmaps, never as an `<img>` or file URL | Right-click "save image", drag-and-drop, browser image cache |
| No storage | Pages are never put in the service-worker cache, localStorage or IndexedDB | Copies left on the device after access is revoked |
| Privacy shield | The page turns fully black when the reader loses focus or is hidden, and when a screenshot shortcut is pressed (Print Screen, Win+Shift+S, Cmd+Shift+3/4/5); print/save shortcuts are blocked; print stylesheet blanks the page | App-switcher thumbnails, desktop screenshot shortcuts and snipping tools, Ctrl+P / Ctrl+S |
| Page text kept server-side | The text of PDF pages is used only for search and returns short snippets | Copying the whole text through the search feature |

**Phone screenshots.** The screenshot buttons on iPhone and Android cannot be detected or blocked
by any website or installed web app: the phone takes the picture without telling the page, so a
black screenshot is not possible from a web app. The watermark on every page (buyer name, masked
number, date, trace ref) is what protects the book there. Making phone screenshots black needs a
native wrapper app (Android `FLAG_SECURE`; on iPhone the most that can be done is to blank the
screen while it is being recorded and to be told after a screenshot).

What still cannot be prevented for PDFs: a phone camera pointed at the screen, the operating
system's own screenshot on phones (Android/iOS do not let web pages block it), and screen recording
software that does not take focus. The watermark is what makes these leaks traceable.

## The "installed app only" rule

Book content is served only to devices that have reported opening the installed app. That report
comes from the app itself, so a technically capable buyer could fake it on their own registered
device. It cannot be used to read on someone else's device: the device key, session and license
checks still apply. The rule exists to keep reading inside the app (no browser tabs to share or
save) and to expire the download page, not as a cryptographic guarantee.

## What is not protected

**Screenshots, screen recording and photos.** Any page shown on screen can be captured. The
reader adds a faint watermark with the buyer's name and part of their number on every page, so a
leaked capture can be traced. That is a deterrent, not a prevention.

**Copying by the legitimate buyer.** The browser receives each chapter as text in order to
display it. A technically capable buyer can use developer tools, a browser extension or a script
to save the text of chapters they are allowed to read. Mitigations: chapters are delivered one at
a time, requests are rate-limited and flagged when unusual, everything is logged, and the owner
can revoke access. Disabled text selection, right-click and copy in the reader are conveniences,
not security.

**Device identity.** The "device" is a key stored in one browser profile. It is not a hardware
identifier. Clearing site data creates a new "device"; the same physical phone with two browsers
counts as two devices. It is not equivalent to Android Keystore or the iOS Secure Enclave, and the
server never uses IP address, user agent or browser fingerprinting as identity (user agent is
recorded only to label devices in the dashboard).

**Buyer handing over their phone or codes.** If the buyer gives someone their WhatsApp access or
reads the code to them, that person can sign in. Device limits make this visible: the buyer loses
access when someone else takes the slot, and the owner gets alerts.

**Content already seen.** Revoking access stops future requests. It cannot remove text that was
already displayed or saved by the user.

**Offline reading.** Not supported, by design. Allowing offline reading would require storing the
book in the browser, where it could be extracted, and a revoked license could not be enforced
until the device reconnects.

**Printing.** Printing is blocked by a print stylesheet. Browser screenshots and "save page" from
developer tools still work.

**Client-side DRM.** Hardware-backed DRM (Widevine, FairPlay) exists for video in browsers, not for
book text. Encrypting chapters for the browser with a key the browser also receives adds no real
protection, so the platform relies on TLS, server-side authorization and per-request signing
instead, and says so.

## Recommended wording for customers

> Your book is available only to you, in a private reader that opens on your registered device.
> It cannot be downloaded as a file, and access links work only with your WhatsApp number.

Avoid claims like "impossible to copy" or "screenshot-proof".
