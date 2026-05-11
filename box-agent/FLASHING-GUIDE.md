# Flashing a mes Box on Raspberry Pi 4

## What you need
- **Raspberry Pi 4** (any RAM size — 2GB is enough)
- **microSD card**, 8 GB or larger (16 GB recommended)
- **Power supply** (official Pi 4 USB-C is best)
- **Ethernet cable** to your home/customer router
- **Computer with an SD-card slot or USB SD reader** to flash

## 5-minute install

### 1. Download the image
Get the latest `.img.xz` from:
```
https://cloud.mes.net.lb/downloads/images/list
```
This returns JSON with the file URL — pick the most recent and download it.

Or directly:
```
https://cloud.mes.net.lb/downloads/images/mes-box-pi4-YYYYMMDD.img.xz
```

### 2. Flash with **Raspberry Pi Imager** (recommended)
- Open Raspberry Pi Imager
- Click **CHOOSE OS** → scroll down → **Use custom**
- Select the `.img.xz` you downloaded
- Click **CHOOSE STORAGE**, pick your SD card
- Click **WRITE**, wait ~5 minutes

(Or with `dd`/`balenaEtcher` — same outcome.)

### 3. Boot the Pi
- Insert the SD card into the Pi
- Plug ethernet into your home router
- Plug in power. Pi boots — wait ~2 minutes for first-boot setup.

### 4. Get the pairing code
Three ways:

**A. Watch the activity LED.** The Pi blinks the 6-character code on the green LED next to the power LED — each character is a series of blinks. Easiest if the Pi is in plain view.

**B. Plug in a monitor + keyboard.** The login banner displays the pairing code prominently:
```
╔══════════════════════════════════╗
║   📦 mes Box — Network Guardian   ║
╚══════════════════════════════════╝

Pairing code: K3M9P2
Enter at: cloud.mes.net.lb/pwa → "Add a box"
```

**C. SSH in (default user `pi`, password `raspberry`).** Then:
```bash
cat /var/log/mes-box/pairing-code.txt
```

### 5. Claim it from your phone
- Open `https://cloud.mes.net.lb/pwa/`
- Sign in with your phone number (use OTP `0000` for now)
- Tap **＋ Add** in the **My box(es)** card
- Enter the 6-character code → **Claim box**
- Done. Within 60 seconds the box appears as "online".

## What happens next

The agent on the Pi:
- Heartbeats to the cloud every 60 seconds
- Discovers devices on your LAN every 5 minutes
- Pulls policy (rules, schedules, blocks) every 60 seconds
- Reports flow telemetry every 5 minutes
- Checks for firmware updates every 6 hours

You can manage everything from the PWA:
- Block YouTube / TikTok / etc. by category
- Schedule "Bedtime" for kids' devices
- Set bandwidth quotas per device
- Block traffic to specific countries
- Generate WireGuard VPN configs

## To make it actually filter traffic

By default the box sees devices on your network (via ARP) but **doesn't sit between them and the internet**. To turn it into a real filter:

**Option A (easiest):** Set the Pi's IP as the **DNS server** in your home router's DHCP settings. Every device that uses DHCP will then route DNS through the Pi.

**Option B (full router mode):** Add a USB-ethernet adapter, plug WAN into eth0, LAN into the USB adapter, configure NAT + DHCP. The agent will start enforcing IP-level blocking via nftables.

## Troubleshooting

- **No pairing code after 5 minutes:** Check that the Pi has internet. SSH in and run `journalctl -u mes-box-agent -n 50`.
- **"code_not_found_or_expired" when claiming:** The code is good for 7 days. After that, reboot the Pi to get a new one (the agent re-registers if no claim happened).
- **Can't SSH in:** Default credentials are `pi` / `raspberry`. Change them with `passwd` after first login.
- **Box appears offline in PWA:** Check the Pi's network. Run `journalctl -u mes-box-agent -f` to watch live logs.
