# Onlive Firmware v1.0

## Contents
 - `Microconsole/onlive.dmp`
    - Contents of the Samsung K9F2G08U0B NAND Flash (with OOB/spare bytes)
 - `Microconsole/analyze.py`
    - End-to-end analyzer: strips OOB, decodes the boot header, dumps the U-Boot
      environment, scans for filesystem signatures, parses the OnLive package
      format, extracts files from both firmware slots, and hunts for
      certificates/keys/configs.
 - `Microconsole/str_grep.py`
    - Tiny "strings + grep" helper for poking around extracted ELFs.

## Notes

 - Use `extract.sh` to reassemble the compressed firmware file from the split
   `console.tar.gz-aa` / `-ab` parts.
 - This seems to be a 2010 version of the Steam Link - https://github.com/ValveSoftware/steamlink-sdk
 - There's a lot of references to GPLv2 within the image, so this repo is licensed under GPLv2.

### Environment

 - **SoC**: Marvell 88DE3010 (codename "Galois" — confirmed by the `galois-rootfs`
   path in U-Boot env and the `galois_shm.ko` kernel module on flash)
 - **CPU**: ARMv5 little-endian
 - **Memory**: 4x1GB DDR2 ELPIDA E1116AEBG
 - **Storage**: Samsung 2GB NAND Flash [K9F2G08U0B] — 2048-byte page + 64-byte OOB,
   131,072 pages, total 276,824,064 bytes raw / 268,435,456 bytes data
 - **Bootloader**: U-Boot (with a Marvell BootROM signed-block header at offset 0)
 - **Linux Kernel Version**: build string `2.6.30-rc4-ptx-mxc1-svn<rev>` (PTXdist-patched)
 - **Build system**: PTXdist / OSELAS by [Pengutronix](http://www.pengutronix.de/software/ptxdist_de.html)
 - **OnLive maintainers**: `david.terra` (onlive package), `remi.machet` (oltools, signrootfs)
 - **GCC**: (CodeSourcery 2006q3-27, Marvell 2007q3-11) 4.1.1
 - **File systems on flash**:
   - Custom OnLive package format for the two firmware slots (see below)
   - YAFFS2 for `/configuration/` (`/dev/mtdblock3`) — runtime writable area in the
     small NAND tail regions
 - **Bluetooth**: BlueZ 2.x stack, chip on `/dev/ttyS1` @ 312500 baud, "ol_bcsp"
   protocol; advertised name `OnLive Microconsole`

### Hashes

```
---shadow- (backup, contains original users; empty MD5 salts — trivially crackable)---
root:$1$$wQCY2EFvsLKFoVcT1e0Kq0:12215:0:99999:7:::
sshd:!:0:0:99999:7:::
ratio:$1$$Ox3sD7SU2sKjDwBMqX2/b0:12215:0:99999:7:::
system:$1$$SPGJYr/enc6gAZU73WtZw/:12215:0:99999:7:::

---shadow (active)---
root:$1$w25wunDK$afkqwthNX7R1yWZzJCrsG.:12215:0:99999:7:::


---passwd---
root:x:0:0:root:/home:/bin/sh
ftp:x:11:101:ftp user:/home:/bin/false
www:x:12:102:www user:/home:/bin/false
sshd:x:100:65534:SSH Server:/var/run/sshd:/bin/false
messagebus:x:103:104:messagebus:/dev/null:/bin/false
rpcuser:x:65533:65534:RPC user:/dev/null:/bin/false
nobody:x:65534:65534:Unprivileged Nobody:/dev/null:/bin/false
```

---

## NAND layout

The dump is a raw NAND read with the 64-byte OOB area interleaved every 2 KB
page. Stripping the OOB yields a clean 256 MB image (`Microconsole/onlive.bin`)
that contains the following regions:

| Offset       | Size      | Content                                                                                |
|--------------|-----------|----------------------------------------------------------------------------------------|
| `0x00000000` | 0x190     | Marvell BootROM signed-block header — 33×12-byte redundant copies, magic `D2ADA3F1`     |
| `0x00170000` | ~11 MB    | Bootloader copy A (TIM + U-Boot, with an embedded gzipped kernel near `0x7AA8F1`)       |
| `0x01A20000` | ~11 MB    | Bootloader copy B (mirror of A)                                                         |
| `0x03C00000` | 4×128 KB  | U-Boot environment — 4 redundant copies, plain ASCII (full env captured in `out/01_uboot_env_*.bin`) |
| `0x04000000` | ~22 MB    | **Firmware slot A** — newer build (`rootfs.version` = `370.81720`, BCD `0x0291`)        |
| `0x08800000` | ~22 MB    | **Firmware slot B** — older build (`rootfs.version` = `331.75378`, BCD `0x0289`)        |
| `0x0D000000` | small     | Misc small chunk                                                                       |
| `0x0DF00000` | small     | Writable area — alternating data/0xFF pattern characteristic of YAFFS2                 |
| `0x0E000000` | ~1.8 MB   | YAFFS2 `/configuration/` partition (mounted from `/dev/mtdblock3`) — slot A copy       |
| `0x0F000000` | ~1.8 MB   | YAFFS2 `/configuration/` partition — slot B copy                                       |

The OOB itself contains only BCH ECC bytes (no YAFFS tags, no JFFS2 nodes). That
is why `binwalk` finds nothing useful on the raw `.dmp` — every 2,048 bytes of
real data are followed by 64 bytes of ECC that fragment any signature scan.

### U-Boot environment

```
bootcmd     = tftpboot 0x1c400000 $(bootfile); bootm 0x1c400000;
bootdelay   = 5
baudrate    = (1 == 0? 14400 : 115200)
preboot     = dhcp
rootpath    = "/home/galois/galois-rootfs"
bootargs    = macaddr=00:82:8A:13:56:4D console=ttyS0,115200
              root=/dev/nfs nfsroot=10.38.54.88:/home/galois/galois-rootfs,v3
              ip=dhcp
ethaddr     = 00:82:8A:13:56:4D
bootfile    = uImage.asic.a0
serverip    = 192.168.0.99
ipaddr      = 192.168.0.101
gatewayip   = 192.168.0.1
netmask     = 255.255.255.0
serial      = 00220AF044D3
```

The default boot command does a **TFTP boot from a development server** — so this
particular dump came from a unit configured for OnLive's internal development
network. Production units boot the on-NAND firmware via U-Boot's `nand read` /
`bootm` path instead.

---

## OnLive package format

Each firmware slot is laid out as a sequence of 2 KB-aligned entries:

```
header page (one 0x800-byte NAND page):
    +0x00  u32  type     (always 0x00000001 in this dump)
    +0x04  u32  attr     (auto-incrementing index across the slot)
    +0x08  u16  0xFFFF
    +0x0A  char name[]   (NUL-terminated ASCII, e.g. "libgcc_s.so")
content pages:
    file bytes, padded with 0xFF to the next 0x800 boundary; the next entry's
    header page starts on that boundary
```

`analyze.py extract slotA` walks every 0x800 boundary in the slot, recognises
header pages by the type/attr/0xFFFF prefix and a printable name, and writes
each entry to `out/slotA/<name>` with a manifest at `out/slotA/_manifest.txt`.
The same applies to `slotB`.

Slot A and slot B are **not strict mirrors** — slot A (newer, 247 entries) ships
the upstream `xpad.ko` plus device nodes `console`/`null`/`zero`; slot B (older,
244 entries) ships an OnLive-customized `ol_xpad.ko` instead. The A/B split lets
the bootloader fall back to a known-good slot if an update is interrupted.

---

## Extraction workflow

```
cd Microconsole
py analyze.py strip-oob       # onlive.dmp -> onlive.bin (data) + onlive.oob.bin (ECC)
py analyze.py parts           # decode the BootROM signed-block header at offset 0
py analyze.py dump-env        # pretty-print the U-Boot environment
py analyze.py scan            # signature scan of the cleaned image
py analyze.py map             # 64 KB-block classification map (zero/0xFF/ASCII/binary)
py analyze.py extract slotA   # walk slot A, write each file to out/slotA/
py analyze.py extract slotB   # same for slot B
py analyze.py find-secrets    # PEM blocks, ASN.1 cert candidates, config markers
py analyze.py carve           # raw region carves (bootloader, env, app slots, tail)
py analyze.py all             # everything except extract/find-secrets/carve
```

Outputs land in `Microconsole/out/`:
 - `out/slotA/`, `out/slotB/` — extracted files plus a `_manifest.txt` per slot
 - `out/00_partition_header.bin` — first 4 KB
 - `out/01_uboot_env_{0..3}.bin` — the four redundant 128 KB env copies
 - `out/02_first_elf_8MB.bin`, `out/03_appA_72MB.bin`, `out/04_appB_72MB.bin`,
   `out/05_tail.bin` — coarse region carves for offline inspection
 - `out/secrets/` — DER cert candidates (most are noise; see "Certificates / keys"
   below)

---

## Findings

### The user-facing GUI client: `rt_client_d`

The main OnLive UI binary — the one that draws the login screen, asks for
username/password, presents the game library, and streams gameplay video — is
**`/client/rt_client_d`** on the device. It lives at `out/slotA/rt_client_d` after
extraction and is **13,844,480 bytes** (by far the largest binary on the NAND).

It is launched by `/etc/init.d/onlive`:

```sh
mount -t yaffs2 /dev/mtdblock3 /configuration/
/home/get_keystore /configuration/AACS/HDCP_Key.store    # HDCP keys for video decode
cd /configuration
/client/ol_btd                                            # Bluetooth daemon (controllers)
/client/rt_client_d                                       # <-- the GUI client
modprobe -r owl_spi
```

(`gcinit` runs in parallel and loads the `owl_spi` / `owl` / `xpad` drivers for
the OnLive Wireless gamepad receiver — "OWL" is the codename for OnLive's
custom 2.4 GHz wireless module.)

String evidence inside `rt_client_d` confirming the role:

| String                                                        | Meaning                              |
|---------------------------------------------------------------|--------------------------------------|
| `/configuration/ol_account.cfg`                               | On-disk account file                 |
| `username`, `password`, `passwordSalt`, `hashedPassword`      | Login form fields                    |
| `predefined_username`, `predefined_password`                  | Debug/preset login overrides         |
| `Please enter password:`, `Enter password`                    | Login UI prompts                     |
| `The password or username you entered is incorrect.`          | Login error message                  |
| `Client cancelled login while collecting pings.`              | Matchmaking queue state              |
| `Client cancelled login while in wait queue.`                 | Matchmaking queue state              |
| `mainmenu.ovd`                                                | Main menu view definition            |
| `button_changelogin_focused.omg`, `navinfo_login.omg`         | Login screen sprites                 |
| `set_input_password_type`                                     | Password input widget                |
| Multi-KB blocks of OnLive Privacy Policy / Terms of Service   | Built-in legal text rendered in UI   |

UI asset extensions: **`.ovd`** = OnLive View Definition (layout), **`.omg`** =
OnLive iMaGe (sprite). These assets are not bundled inside `rt_client_d`; they
live on the YAFFS2 `/configuration/` partition or are fetched from the OnLive
servers at runtime.

ELF: ARM little-endian, EXEC type, entry point `0xE8E0`. Open in Ghidra/IDA to
RE the login flow.

### Other notable binaries

| Binary             | Size        | Purpose                                                |
|--------------------|-------------|--------------------------------------------------------|
| `rt_client_d`      | 13.8 MB     | Main GUI / streaming client (above)                    |
| `libPE.so`         | 1.2 MB      | "Player Engine" — video playback / streaming library   |
| `libol_input.so`   | 116 KB      | OnLive input handling                                  |
| `ol_btd`           | 372 KB      | OnLive Bluetooth daemon (custom, replaces `hcid` for OnLive's controller pairing flow) |
| `get_keystore`     | small       | Pulls HDCP / AACS keys into `/configuration/AACS/HDCP_Key.store` before client launch |
| `mc_hwinit`        | small       | MicroConsole hardware init (called as `mc_hwinit 3`)   |
| `mc_update`        | small       | MicroConsole firmware updater                          |
| `owl_monitor`      | small       | OWL wireless module monitor                            |
| `owl_gamepad_full_enc.owl`, `owl_host_full_enc.owl` | — | Encrypted OWL MCU firmware blobs |
| `owl.ko`, `owl_spi.ko` | small   | OWL wireless driver (SPI-based)                        |
| `HDMI_Service`, `SetRes`, `FilePlayer`, `mpeg2VideoPlayer` | small | Display / playback helpers |

### Slot inventory (slot A, 247 entries)

 - 69 kernel modules (`.ko`) — crypto, NLS, DVB, USB, plus OnLive's `galois_shm.ko`
 - 14 shared libraries (`.so`) — glibc, libstdc++, libdbus, libbluetooth, libPE, libol_input
 - 23 ipkg `.control` + 23 `.list` files (PTXdist/OSELAS package manifests)
 - System configs: `passwd`, `shadow`, `shadow-`, `group`, `fstab`, `inittab`,
   `hosts`, `nsswitch.conf`
 - Service configs: `bluetooth.conf`, `hcid.conf`, `rfcomm.conf`,
   `dbus-1/system.conf`, `dbus-1/session.conf`, `ser2net.conf`
 - Init scripts: `rcS`, `gcinit`, `bluetooth`, `dbus`, `onlive`, `resetbt`, `mdev`

### Certificates / keys

**No PEM-formatted certificates or keys are stored anywhere on the NAND.** Every
`PRIVATE KEY` / `PUBLIC KEY` string hit was an OpenSSL string constant
(`PKCS8`, `X509`, etc.) embedded in libcrypto, not actual key material. The
ASN.1/DER candidates saved under `out/secrets/` are almost certainly noise.

The Microconsole receives its TLS material at runtime — `rt_client_d` connects
to OnLive's servers and the AACS/HDCP keys come via the `get_keystore` helper
into the YAFFS2 `/configuration/AACS/` directory. The hardcoded date `2010-09-28`
in `/etc/init.d/onlive` exists *specifically* so the very first cert validation
after a cold boot does not fail before NTP can sync.

The only credential material on flash is the MD5-crypt hashes in
`out/slotA/shadow` and `out/slotA/shadow-` (reproduced in the **Hashes**
section above; the `shadow-` backup uses empty salts and is trivially crackable).

---

### TODO
 - Extract firmware from the controller (the OWL gamepad MCU firmware blobs
   `owl_gamepad_full_enc.owl` / `owl_host_full_enc.owl` are encrypted on the
   NAND — find the OWL-side key).
 - Parse the YAFFS2 `/configuration/` partition (regions at `0x0E000000` /
   `0x0F000000`) to recover `ol_account.cfg`, the AACS keystore, and any
   cached `.ovd` / `.omg` UI assets.
 - Reverse `rt_client_d`'s login flow and the OnLive RTSP-like streaming
   protocol it speaks to the OnLive servers.
 - See if it's possible to transform an Onlive Microconsole into a [Steamlink](https://www.youtube.com/watch?v=uOa-ObWPAKg).
