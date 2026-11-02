# Administrator manual

This is the book owner's guide to the management dashboard (`https://admin.example.com`, or
`/admin` on a single domain).

## First sign-in

1. Sign in with the account created during deployment.
2. Open **My Account** → *Set up two-factor authentication*. Add the key to an authenticator
   app and enter the 6-digit code.
3. Change the temporary password if you were given one.

## Setting up your book

1. **Books** → fill in title, author, price, currency and description → *Create book*.
2. On the book page:
   - **Cover**: upload a PNG, JPEG or WebP image.
   - **Upload a new edition**: choose the EPUB (recommended) or PDF. The file is checked,
     encrypted and prepared for reading. When it shows **READY**, customers can read it.
   - *Devices per purchase* (default 1) and *License duration* (empty = never expires) apply
     to new purchases.
3. Click **Publish** so the book appears on the download page.

**EPUB or PDF?** EPUB gives the best reading experience: text resizes, search works, dark mode
looks right. PDF pages are shown as images: the layout stays exactly as designed, but text
cannot be resized or searched.

**Replacing the book file**: upload a new edition. Customers who already bought the book keep
their access and see the new edition. You can switch back to an older edition under
**Editions** → *Make current*.

## Download page and WhatsApp

**Download Page & WhatsApp** in the dashboard:

- *Book shown on the download page*: the book visitors see at the customer site's home page.
- *Business WhatsApp number* and *Prefilled order message*: used by the "Buy this book on
  WhatsApp" button that visitors without access see.
- *Invitation message*: the text you send with each private link. It must contain
  `{invitation_link}`.

## How PDF books are protected

- The uploaded PDF is encrypted and never sent to any browser, not even the buyer's.
- Each page is shown as an image stamped with the buyer's name, part of their number and a
  **watermark ref** (for example `FAAB80E5`).
- If you find a leaked photo or screenshot of a page, open **Reading Licenses** and enter the
  ref printed on it: the buyer it belongs to is shown. You can then suspend or revoke them.

## Selling: from order to reader

1. A customer orders on WhatsApp and pays.
2. **Orders** → *Register a customer and order*: name, WhatsApp number, book, amount, payment
   method and reference.
   - If you have already confirmed the payment, choose *Verified*.
   - Otherwise leave it *Pending*; it appears under **Payment Verification**.
3. Open the order, check the money arrived, confirm the reference, click
   **Mark payment as verified** (or **Reject payment** with a reason).
4. Under *Reading access*, click **Generate Access Link**. Choose how long it stays valid
   (24 hours by default).
5. In the window that opens, click **Send via WhatsApp** (opens WhatsApp with the message ready),
   or copy the message. **The link is shown only once.**

The customer opens the link, confirms their number with a code, and starts reading.

### When something goes wrong

| Situation | What to do |
|---|---|
| Link expired or lost | Order page → *Generate new access link*, or **Access Invitations** → *Reissue*. The old link stops working. |
| Customer typed the wrong number when ordering | Customer page → change the WhatsApp number (pending invitations are cancelled), then generate a new link |
| Customer already activated and asks for the link again | They don't need it: they open the reader app or the customer site and sign in with their number |
| Customer has a new phone | They sign in on the new phone; they can move access themselves up to the monthly limit. Otherwise approve it under **Registered Devices** |
| Customer wants two devices | **Reading Licenses** → *Devices allowed* → 2 |
| Refund | **Reading Licenses** → *Revoke* (or customer page → *Revoke all access*) |
| Suspected sharing | Customer page → *Suspend access*, review **Security Events**, then reactivate or revoke |

## Pages

| Page | Use it to |
|---|---|
| Overview | See live totals and recent activity and alerts |
| Orders / Payment Verification | Register orders, verify or reject payments, issue links |
| Customers | Search, filter and sort customers; open one for orders, licenses, devices and full history |
| Access Invitations | See every link's status (pending, used, expired, revoked); revoke or reissue |
| Registered Devices | See each reader browser; revoke one; approve or reject device moves; replacement history |
| Reading Licenses | Suspend, reactivate, renew, revoke, change devices allowed |
| Reading Activity | Access events (opened invitation, verified, opened book, opened chapter…). An opened chapter is not proof it was read. |
| Security Events | Alerts: repeated wrong codes, reused or expired links, unknown devices, many sessions, suspended accounts trying to read, unusual request volume, unauthorized content requests. *Resolve* with a note once handled. |
| Audit Logs | Who did what and when. Entries cannot be edited or deleted. |
| Administrators | Add staff. **Owner**: everything. **Manager**: daily operations, no staff or system settings. **Support**: read-only. |
| System Settings | Access rules (below) |

## System settings

| Setting | Default | Meaning |
|---|---|---|
| Default invitation validity | 24 h | How long a new link works |
| Verification code validity | 10 min | |
| Wrong code attempts allowed | 5 | Per code |
| Codes per hour | 5 | Per customer |
| Seconds between code requests | 60 | |
| Reading session length | 168 h (7 days) | After this, the customer confirms their number again |
| Sign out after inactivity | 4320 min (3 days) | |
| Default devices per purchase | 1 | |
| Moving access to a new device | Customer can move it | Or *Requires my approval* |
| Self-service device moves per 30 days | 2 | After this, moves need your approval |
| Default license duration | none | |
| Reader requests per minute | 120 | Above this, reading pauses briefly and an alert is raised |
