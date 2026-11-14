# Native Windows client

Current WinUI2.6.5 client connects directly to <backend-host>:7443 through
independent pinned TLS media/input connections. No SSH dependency or static IP.

See [project guide](../docs/PROJECT.md) for architecture, configuration, launch and
checks; [current evidence](../evidence/README.md) for tested results/limits.
Normal launch starts disconnected.
Build targets Windows11 x64; use existing locked dependencies and installed tools.
Historical proposals/source snapshots are in the verified archive.
