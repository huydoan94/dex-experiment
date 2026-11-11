# Evidence: current state

[results.json](results.json) holds the deployed identities and key measurements;
[checks.log](checks.log) gets one line per check or deployment from 2026-11-07 on.
How each problem was fixed: [docs/FIXES.md](../docs/FIXES.md). Full history is kept outside this repository.

## Running now

| Part | Identity |
| --- | --- |
| Backend on the backend machine | dexd 82cba96c, kms_daemon_live b0804406, kms_daemon_probe 76da72e6, kms_session_live 94d8e954, direct_gateway 2451bdeb, clipboard_bridge 4471c768, file_bridge 1afc3615, site_env 4787c7ff (all files: [MANIFEST.sha256](../research/native-usb/MANIFEST.sha256)); `before-*-2026111x` rollbacks; time zone, phone serial and sink name come from a local config file |
| Windows client | v7 (packaged ZIP `7e6f9d9c…66ca`, not in this repository); v15 test package adds system keys, clipboard text and files PC to phone |
| Behaviour | async USB in/out, scrambled RTP, pause on disconnect / resume on connect, replug after a session ends, pointer shapes, low-latency video, adaptive audio, system keys, clipboard text both ways, files PC to phone (copy-paste, drag and drop, delivery progress) |

## Open

- Long pause (minutes to hours) not yet observed.
- Phone connect refusal is avoided by replugging; cause unknown.
- No physical/optical latency or listening measurement (user feel is the test).
- 19 older test modules need capture folders archived on 2026-11-06.
- Files phone to PC not built (docs/FILE_TRANSFER.md); it needs usb_tunnel to count open phone-initiated connections, not a lifetime total of 16 (sessions use 1 today).
- Resolution: the phone, not the PC, picks from the offered list; it gave DeX on PC only
  1080p30 (720p60 and 1080p60 refused, 2026-11-10). `video_mode` site setting kept for tests.
- Windows build machine is Windows 10; the app declares Windows 11 as minimum. Release
  build, 190 session checks and the v7 app launch (to Disconnected) work there (2026-11-10).
