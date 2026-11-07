# DeX remote desktop

Samsung DeX from a phone on a Windows 11 PC. The phone is plugged into a small
Linux machine that runs the Python backend; the Windows app connects to it
over two TLS connections (video/audio and input).

This repository is the research project. Data is saved in another container.

## Folders

| Folder | What is in it |
| --- | --- |
| [docs/](docs/) | [PROJECT.md](docs/PROJECT.md) how it works and how to change it · [FIXES.md](docs/FIXES.md) every fixed problem · [LESSONS.md](docs/LESSONS.md) rules not to repeat · `agents/` agent startup files |
| [evidence/](evidence/README.md) | what is running now, open items, compact results |
| [research/native-usb/](research/native-usb/README.md) | backend source and tests |
| [windows/](windows/) | Windows client source (C#, WinUI) and packaging scripts |
| [android/blackscreen/](android/blackscreen/) | phone app that keeps the phone screen black during DeX |
| [scripts/](scripts/) | `lab/` SSH helpers · `host/` host-side setup files · `gateway/` gateway test · `viewer/` old Python viewer · docs check |
| [design-reference/](design-reference/) | UI mock-ups |

Root files: [CODEX_HANDOFF.md](CODEX_HANDOFF.md) current state and next steps ·
[AGENTS.md](AGENTS.md) rules for agents · `dex_probe.py` backend helper.

## Use it

Build the client from `windows/` (see [windows/README.md](windows/README.md)),
then run `DexClient.App.exe` and Connect. Disconnecting pauses DeX; reconnecting
resumes it in about a second.
