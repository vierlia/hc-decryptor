# hc-decryptor

A terminal tool for reading, editing and repacking `.hc` config files from the
terminal.

Use it on configs you own: read the payload/server/protection fields, lift
expiry and device locks, and write the result back as a valid `.hc` file.

Not affiliated with, endorsed by, or connected to the authors of any VPN or
proxy app. Independent project, no commercial intent.

## Build

```
go build -o hcdecryptor.exe .
```

## Usage

```
hcdecryptor.exe config.hc          # TUI: view & edit fields
hcdecryptor.exe -json config.hc    # print decrypted config as JSON
hcdecryptor.exe -unlock config.hc  # strip protections, save config.unlocked.hc
hcdecryptor.exe -unlock -name MyName -o new.hc config.hc
```

In the UI: numbered menu, Terminal UI Style. `1` opens a `.hc`, `2` lists all
decrypted fields, `3` strips protections (expiry -> lifeTime, device/account
locks released), `4` edits one field, `5` writes a new `.hc`, `6`/`q` quits.
You can drag a file onto the terminal or paste its path — quotes and `file://`
prefixes are handled.

## How the .hc format works

Three layers, all symmetric so the file can be repacked:

1. 11-byte cycling XOR (`e382e4b8adc386f09f9293`) over the latin-1 bytes of the
   file's UTF-8 text -> hex string.
2. ChaCha20 (DJB variant, nonce `db`x8, counter starts at 1, trailing 16 bytes
   dropped) with hardcoded keys -> outer JSON holding `a/xy/uv` (old format) or
   `cfg.content` (new format).
3. Content is split on the `uv` delimiter; each token is decoded per-field
   (ChaCha20 with derived nonce + JKL bit transform + double base64).
   SSH/VPN credentials use `z3a` encoding (pairs `a.b` -> byte `(a>>b)&0xff`).

Protection flags that can be cleared: `expiryTime` (set to `lifeTime` — a value
the format itself defines for "no expiry"), `blockedByHwid`,
`blockedByPassword`, the `lockAllConfig`/`unlockUserAndPass` flags, and the
`bb/e/fe/ed` meta fields in the outer JSON.

Note: the SSH account has its own lifetime on the server side — that is outside
the file. If the account dies, replace the `sshField` value via the TUI.

## New format (`cfg.content`)

The decryption path (RST: cycling XOR -> base64 -> AES-128-ECB, with a ChaCha
fallback) is supported for reading. Repacking this format is not — it fails with
a clear error instead of producing a broken file.

## Credits

This is a rewrite, not a port. The cryptographic constants and the wire format
were derived from the public work below, which itself comes from reverse
engineering:

- HCTools/hcdecryptor (GPL-3.0) — https://github.com/HCTools/hcdecryptor
- CONIGUERO/HCDecryptor (GPL-3.0) — https://github.com/CONIGUERO/HCDecryptor
- PANCHO7532/HCDecryptor — https://gitlab.com/PANCHO7532/HCDecryptor

Because it reuses those constants, this project is released under the same
license (GPL-3.0); see `LICENSE`. No original code from the projects above is
copied into this one.

Configs that fail to decode are rejected rather than guessed at.
