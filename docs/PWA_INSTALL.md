# Installing the reader (PWA)

The reader is a Progressive Web App: it installs from the browser, with no app store. Installing
adds a **My Books** icon that opens straight to your book. Nothing is downloaded except the app
itself; the book stays protected on the server.

The reader also shows these steps itself: the **DOWNLOAD BOOK** button and the
*Install the reader* option in reading settings open them, and `/install` lists every platform.

| Platform | Browser | Steps |
|---|---|---|
| Android | Chrome, Edge, Samsung Internet | Tap **DOWNLOAD BOOK** → **Install Reader**. Or menu ⋮ → *Install app* / *Add to Home screen*. |
| Android | Firefox | Menu ⋮ → *Install* (or *Add to Home screen*) |
| iPhone / iPad | Safari (iOS 16.4+ for other browsers) | Share ⬆ → *Add to Home Screen* → *Add*. Then open **My Books** and sign in once with your number. |
| Windows / ChromeOS / Linux | Chrome, Edge | Click **Install Reader**, or the install icon at the right of the address bar |
| macOS | Chrome, Edge | Same as Windows |
| macOS | Safari 17+ | File → *Add to Dock* |
| Desktop | Firefox | Not supported. Read in the browser, or use Chrome, Edge or Safari to install. |

## What the app does when opened

1. Checks the signed-in session with the server.
2. Checks this device is registered and the license is active.
3. Opens your book (or your library if you bought several).
4. If the session has ended, asks for your WhatsApp number and a code. No new invitation or
   purchase is needed.

The app's start address is `/app`. It never contains your invitation link.

## Technical details

- Manifest: `/manifest.webmanifest` (`display: standalone`, `start_url: /app`, scope `/`, icons
  192/512 and a maskable 512).
- Service worker: `/sw.js`. It caches only the app shell (HTML shell, scripts, styles, icons).
  It never caches API responses, book content, covers or invitation pages. Offline, the app
  opens and asks you to reconnect.
- On iOS the installed app has its own storage, separate from Safari, so it counts as a new
  device the first time. With the default policy, the customer moves access to it themselves.
