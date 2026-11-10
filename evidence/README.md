# Evidence: current state

[results.json](results.json) holds the deployed identities and key measurements;
[checks.log](checks.log) gets one line per check or deployment from 2026-11-07 on.
How each problem was fixed: [docs/FIXES.md](../docs/FIXES.md). Full history is kept outside this repository.

## Running now

| Part | Identity |
| --- | --- |
| Backend on the backend machine | dexd `5bd8d746`, kms_daemon_live `e061b6af`, kms_daemon_probe `810bc806`, direct_gateway `99d3cc48` (all files: [MANIFEST.sha256](../research/native-usb/MANIFEST.sha256)); previous two versions kept as rollbacks; time zone and phone serial come from a local config file |
| Windows client | v7 (packaged ZIP `7e6f9d9c…66ca`, not in this repository); v8 test adds system keys |
| Behaviour | async USB in/out, scrambled RTP, pause on disconnect / resume on connect, replug after a session ends, pointer shapes, low-latency video, adaptive audio |

## Open

- Long pause (minutes to hours) not yet observed.
- Phone connect refusal is avoided by replugging; cause unknown.
- No physical/optical latency or listening measurement (user feel is the test).
- 19 older test modules need capture folders archived on 2026-11-06.
- Client features still to do: clipboard sync, resolution choice, file drag and drop.
- Windows build machine is Windows 10; the app declares Windows 11 as minimum. Release
  build, 190 session checks and the v7 app launch (to Disconnected) work there (2026-11-10).
