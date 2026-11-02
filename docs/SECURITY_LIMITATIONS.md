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
| A forwarded invitation can't be claimed by someone else | Code sent only to the buyer's WhatsApp number | Strong, unless the buyer also forwards the code |
| A shared reader URL shows nothing | Every content request needs session + registered device key + license | Strong |
| A stolen session cookie doesn't work alone | Requests must be signed with the browser's non-extractable device key | Good against cookie theft; not against malware controlling the browser |
| Access can be withdrawn | Revocation, suspension and device removal take effect on the next request | Strong for future reading; see below for what was already seen |
| One purchase, one device | Device limit per license, controlled device moves, alerts | Moderate (see "Device identity") |

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
