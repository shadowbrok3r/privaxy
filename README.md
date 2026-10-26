<div align="center">
  <img src="https://user-images.githubusercontent.com/45085843/146658168-a4770cf5-e1b1-40e6-8931-ffc64d3d4936.png">

  <h1>Privaxy</h1>

  <p>
    <strong>Next generation tracker and advertisement blocker</strong>
  </p>
</div>

<div align="center">
<img width="868" alt="dashboard" src="https://user-images.githubusercontent.com/45085843/210057822-f8a1e355-1b4d-4c48-a8c6-d72388e3b648.png">
<img width="912" alt="requests" src="https://user-images.githubusercontent.com/45085843/210057831-6c6b4aac-245c-4964-9d34-bcbd87d00a5f.png">
<img width="912" alt="filters" src="https://user-images.githubusercontent.com/45085843/210057827-9a413c82-77dd-4aaa-a7db-e12f0045608f.png">
<img width="912" alt="exclusions" src="https://user-images.githubusercontent.com/45085843/210057826-88168855-ac3e-4117-9d27-34199c39a7f3.png">
<img width="868" alt="custom_fiters" src="https://user-images.githubusercontent.com/45085843/210057820-d666baa5-4f63-45ca-ad2d-9eca95590100.png">
<img width="666" alt="taskbar" src="https://user-images.githubusercontent.com/45085843/210057833-df002cfd-aecf-4d67-bdd6-225ac3d6b980.png">
</div>

## Native desktop and Android pairing

Run `cargo run -p privaxy-app`. Cargo fetches egui-theme-kit from
[its Git repository](https://github.com/shadowbrok3r/egui-theme-kit) at the revision
pinned in `app/Cargo.toml`. The default desktop UI includes custom window chrome
and the theme preset picker under Settings. The previous Dioxus UI remains available with
`cargo run -p privaxy-app --features legacy --bin privaxy-legacy`.

The title bar has **Dashboard**, **Traffic**, **Settings**, and **Logs**.
Dashboard combines proxy controls, filtering, Android connection status, a live
request chart, top destinations, and recent requests. Settings contains appearance,
filter lists, custom rules, and HTTPS inspection. Navigation and actions use the shared
Git-pinned SVG icon pack, tinted by the selected theme.

Traffic uses the Git-pinned egui-data-table and egui_json_tree forks. Click a request
to open its docked inspector; drag the divider to resize it. Right-click a column
header to hide/show columns, drag headers to reorder, or drag borders to resize.
Search covers all columns, request/response headers and trailers, capture errors,
notes, and complete retained body bytes. Body searches run in the background, including
content beyond the inspector's current page; encrypted or uncaptured content cannot match.
Use **Column filters** to combine text filters for any column, including hidden columns.
The popup stays open while typing and closes with **Done**, Escape, or an outside click.
Presets include **All requests**, **Hide errors**, **Errors**, **Blocked**, **Slow (≥ 1 s)**,
**Pending**, and **JSON responses**; they combine with text and column filters.
**Reset filters** clears all filters. CONNECT handshakes are hidden initially.
**Follow new requests** keeps matching arrivals in chronological order and scrolls to them
without changing the selected inspector. Turn it off to browse and sort manually; turning
it off restores the manual table's sort and column layout.
Scrollbars remain visible with contrasting handles, including on wide tables.
Request/response views include headers, duplicate
header values, bodies, timing, client, status and capture errors. JSON has a
collapsible searchable tree and formatted copy. HTML, JavaScript, TypeScript, CSS, XML,
and JSON source use syntax highlighting; hexadecimal views color offsets, byte classes,
and the ASCII column. **Pretty** uses parser-based HTML/XML and JavaScript/TypeScript
formatters on complete bodies up to 2 MiB, with an 8 MiB output limit. Formatting and
highlighting run off the UI thread, with only visible lines laid out. Unsupported or
incomplete content falls back to source without changing the captured bytes.
Raw text/hex bodies use 64 KiB pages. Complete JSON up to 8 MiB uses the tree; larger
bodies remain available through paging and full body export. Capture retains up to 5,000 requests and 512 MiB of
body data per session; reaching a limit is explicit and does not stop forwarding.
Clear session releases the capture and begins a fresh one. TLS passthrough and
upgraded protocol frames are labelled as not decoded.

**Logs** provides Error/Warn/Info/Debug/Trace capture levels, search, pause, copy
and export. The level persists across restarts. Debug records connection stages;
Trace adds heartbeat timing. Desktop writes private files to the OS cache directory
(`~/.cache/privaxy/logs/desktop.log` on Linux), rotating two 5 MiB files. Export
includes both files, including previous runs. Android provides the same controls
under **Settings → Diagnostic logs**, also reachable from Pairing, and exports to
Downloads. Pairing credentials, headers and body payloads are not diagnostic events;
connection endpoints and errors are included. A bounded queue reports any dropped
file lines in the UI/export instead of blocking network workers.

For desktop use, the proxy starts automatically on `127.0.0.1:8100`. Dashboard's
**Desktop proxy** panel connects apps in several ways; each control's hover hint explains it.

- **System proxy** points the KDE (`kioslaverc`) and GNOME (GSettings) proxy settings at
  `127.0.0.1:8100` for apps that follow the desktop setting. The previous settings are kept in
  `~/.privaxy/system-proxy-backup.json` and restored when you switch it off or quit; the choice
  is applied again at the next start.
- **Network capture** (Linux) reaches apps that ignore proxy settings. Privaxy moves itself into
  a child cgroup, then a helper started through pkexec (administrator password) installs the
  nftables table `inet privaxy_capture`. It redirects the current user's outbound TCP on port 80
  and the inspected ports to `127.0.0.1:8103` / `[::1]:8103` and refuses UDP 443, so QUIC falls
  back to TCP. Privaxy's own connections, other users and loopback are exempt. The table is
  owned by the helper's `nft` session, so the kernel deletes it as soon as capture is switched
  off or Privaxy, the helper or `nft` exits, even when one of them is killed.
  The capture listener reads each connection's original destination and TLS server name, then
  decrypts or passes it through exactly as it would a CONNECT.
- **LAN devices** also listens on every interface, port 8100, for the addresses under
  **Settings → LAN devices** (private, Tailscale and link-local ranges by default); loopback is
  always allowed. Point a device's Wi-Fi proxy at this computer, and download the CA from
  `http://<this computer>:8100/privaxy-ca.crt`.
- **Inspected browser** starts Chromium, Chrome, Brave, Edge or Vivaldi with its own profile,
  the proxy, and the inspection CA trusted by its key hash, so nothing is installed system-wide.
- **Copy terminal setup** copies `export` lines for the proxy variables and CA bundles
  (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, …),
  written to `~/.privaxy/`. They last for the shell you paste them into.
- **Export CA** saves the inspection CA for manual installation.

**Test proxy** sends a real HTTP request through the listener. **Stop proxy**
closes the listener, active HTTP/CONNECT streams, and Android relay; **Start proxy**
reopens it without clearing statistics or reinitializing filters. Bind errors
appear on Dashboard and can be retried after freeing the port. Android is optional.

Enable **Observe only · no blocking** on Dashboard to keep inspection and capture while
disabling ad/tracker decisions and HTML rewriting. The preference survives restarts and
also applies to traffic from paired phones. Clients must still trust the desktop CA;
excluded hosts pass through encrypted with metadata only. This option does not change
routing or firewall rules; **Network capture** does.

**Settings → HTTPS inspection** decides which CONNECT tunnels are decrypted. Only ports in
**Inspect ports** (443 and 8443 by default) are; other ports, such as Google push on 5228,
pass through untouched. When a client refuses the inspection certificate, whether with a TLS
alert, by hanging up during or right after the handshake, or by not answering it, as pinned
apps such as Instagram and curl do, the host's whole registrable domain (`cdninstagram.com`
for every `scontent-*.cdninstagram.com` shard) passes through encrypted on that port for the
rest of the session instead of failing on every retry. Dashboard reports how many domains did
this; Settings lists them beside **Never intercept**, with a button that adds `*.domain` (which
also covers the bare domain) and **Retry** to inspect them again. Turn off **Pass through
domains that refuse the certificate** to keep failing them instead. Tunnels that are not
decrypted are still checked against hostname rules and refused when one matches.

Decrypted sessions negotiate HTTP/2 when the client offers it. gRPC calls are forwarded over
HTTP/2 with their trailers in both directions, so they are inspected instead of broken.

**Decrypt these Android apps** lists the packages, `*` wildcards allowed, whose connections
from a paired phone are decrypted. It defaults to common browsers, the only Android apps that
trust user-installed CAs. The phone names the app behind each relayed CONNECT (`Privaxy-App`),
so every other app's connections pass through encrypted from the first byte instead of failing
once per domain. The traffic table's **Client** column shows the app.

1. Use **Android connection** on Dashboard (clicking Android status in the title bar
   opens Dashboard). Hover its controls for help. The computer's Tailscale IPv4 address is selected
   automatically when available, otherwise a LAN address. Every active IPv4 address
   is listed with its interface name, including separate Ethernet and Wi-Fi addresses
   and any aliases. VPN/VM/container addresses appear under **Other** and are not
   chosen as defaults. Click the address reachable from your phone to fill the field;
   use the refresh button after changing networks (it keeps your selected address).
   Android must be connected to the same tailnet to use the
   Tailscale address, or the same reachable LAN to use the LAN address. **Start relay**
   listens on all interfaces at `0.0.0.0:8101`. Pairing codes contain
   the selected address. The regular HTTP proxy stays on `127.0.0.1:8100`.
2. **Show QR** and scan it with the phone camera to open Privaxy directly on **Pairing**.
   Review the desktop's name and address and tap **Add desktop**. Alternatively **Copy link**
   and paste it into **Paste pairing code**. Existing `privaxy-pair-v1:` codes still work.
   The phone keeps every desktop it pairs with, such as a home and a work computer, under
   **Paired desktops**, and **Use** picks the active one. While the active desktop is
   unreachable, the phone moves to the next reachable one and makes it active; turn off
   **Switch to another paired desktop** to stay on one. Pairing again after revoking a
   desktop's pairings replaces its old entry. Under **Active desktop**, edit
   **Desktop IP or hostname** and **Relay port**, then **Save name and address** to switch
   networks without replacing the pinned certificate.
   The authenticated relay automatically sends its public inspection CA to updated Android
   clients. Use **Pairing → Install desktop CA** on the phone, then approve the downloaded
   certificate in Android Security settings. Installation is checked separately from pairing
   and from Android's local CA. The CA is cached and refreshed on reconnect and periodically;
   a changed CA prompts installation again. Each paired desktop has its own CA to install.
   Neither CA private key leaves its device.
3. Enable **Route captured TCP traffic through desktop**. On LAN, enable
   **Capture all traffic** on Dashboard. With the Tailscale Android VPN, leave
   capture off and point proxy-aware apps at `127.0.0.1:8100`. Keep Privaxy included
   in Tailscale routing. Pairing and the routing preference survive restarts.
4. Export the desktop inspection CA from Settings and install/trust it on clients
   requiring HTTPS inspection. Pairing's transport certificate is pinned separately;
   it does not install the inspection CA or bypass app certificate pinning.

Requests appear in the desktop log while routing is enabled. DNS and other UDP
remain direct; the Android QUIC setting can force compatible apps to TCP. If the
relay is unavailable, TCP fails instead of silently bypassing it. Disable the relay
to close active paired connections, or revoke all pairings to rotate its credentials.
The relay must be enabled again after restarting the desktop app.

Navigation and connection status live in the title bar. Green **connected · paired**
means the phone authenticated and exchanged a heartbeat over pinned TLS, even when
there is no HTTP traffic. Android distinguishes an offline saved pairing from a
verified live connection and retries automatically. Desktop retains verification
for the current session; restarting it waits for the phone to authenticate again.
Connection loss is detected within about 8 seconds on Android and 12 seconds on
desktop; closing the app or disabling/revoking the relay closes the connection.
On Android, **Check connection** retries immediately without removing the saved
pairing. A connection error identifies the saved endpoint. **No route to host**
means network reachability failed before TLS authentication; check Wi-Fi client
isolation and firewall access to TCP 8101. If the desktop is using a Tailscale
exit node, enable its **Allow LAN access** option. Matching IP subnets or a saved
pairing alone do not establish that the relay is reachable.

Android permits one VPN per profile. Privaxy's **Capture all traffic** mode and
the Tailscale Android VPN cannot run together. Use the LAN address for full-device
capture unless the phone's network already routes to the tailnet. Tailscale pairing
requires a reachable tailnet route; selecting the address does not create one.
App split tunneling does not allow two Android VPN services to run together.
Allowing Tailscale IPs through a filter cannot create a tailnet route after its VPN
is replaced. A LAN connection, a tailnet-routing gateway, or proxy-only mode avoids
that conflict.

## About

Privaxy is a MITM HTTP(s) proxy that sits in between HTTP(s) talking applications, such as a web browser and HTTP servers, such as those serving websites.

By establishing a two-way tunnel between both ends, Privaxy is able to block network requests based on URL patterns and to inject scripts as well as styles into HTML documents.

Operating at a lower level, Privaxy is both more efficient as well as more streamlined than browser add-on-based blockers. A single instance of Privaxy on a small virtual machine, server or even, on the same computer as the traffic is originating from, can filter thousands of requests per second while requiring a very small amount of memory.

Privaxy is not limited by the browser’s APIs and can operate with any HTTP traffic, not only the traffic flowing from web browsers.

Privaxy is also way more capable than DNS-based blockers as it is able to operate directly on URLs and to inject resources into web pages.

## Features

- Suppport for [Adblock Plus filters](https://adblockplus.org/filter-cheatsheet), such as [easylist](https://easylist.to/).
- Web graphical user interface with a statistics display as well as a live request explorer.
- Support for uBlock origin's `js` syntax.
- Support for uBlock origin's `redirect` syntax.
- Support for uBlock origin's scriptlets.
- Browser and HTTP client agnostic.
- Support for custom filters.
- Support for excluding hosts from the MITM pipeline.
- Support for protocol upgrades, such as with websockets.
- Automatic filter lists updates.
- Very low resource usage.
  - Around 50MB of memory with approximately 320 000 filters enabled.
  - Able to filter thousands of requests per second on a small machine.

## Installation

### Using a pre-built binary

Pre-built binaries for major operating systems and platforms are provided at [github releases](https://github.com/Barre/privaxy/releases).

### Local system configuration

1. Go to the GUI, click on "Save CA certificate".
2. Install the downloaded certificate locally.
    - Macos: <https://support.apple.com/guide/keychain-access/add-certificates-to-a-keychain-kyca2431/mac>
    - Linux: `cp privaxy_ca_cert.pem /usr/local/share/ca-certificates/`
3. Configure your local system to pass http traffic through privaxy which listens on localhost:8100.
   - Macos: <https://support.apple.com/guide/mac-help/change-proxy-settings-network-preferences-mac-mchlp2591/mac>
   - Ubuntu (gnome): <https://phoenixnap.com/kb/ubuntu-proxy-settings>
