# Supplied native-client UI reference

User requested the Windows-host reference and explicitly authorized getting it this time. The matching file was `D:\Remote Desktop UI.html` (extension was omitted in chat). Copied read-only once into this project. SHA256: ca4ee69b4276fd25c796f195108019cc480df721d57f43ace88a641c2ae0a568. No host file was changed; no further host access is needed or authorized by this exception.

`reference.html` is the complete original bundle including notices. `screen-0.html` through `screen-3.html` are extracted authored templates for Home, Remote view, Telemetry open and Toolbar hidden. They retain bundled resource identifiers and are source references, not standalone runnable exports. The original bundle renders the complete boards.

Native mapping: dark #0E0F11 home with centered blue Connect; edge-to-edge desktop with floating #16181C toolbar, red Disconnect, hide/show handle and telemetry dialog. The client uses existing native typography and truthful runtime counters. The optional cursor indicator shows local input position; no phone cursor synchronization or invented latency/network values are implied. Settings still load from the established backend.json file, without exposing its contents in the product UI.
