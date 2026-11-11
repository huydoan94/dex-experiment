# File copy and drag and drop: protocol map

Work in progress. Text clipboard is done (clipboard_bridge.py); files follow the
official app's own path. Sources: phone DeX app (KMSServiceManager e2/s,
ClipboardTaskManager l2/b, r2/k, KMSService), phone native SideSync library,
the PC app and its NativeSamsungDexFramework.dll.

## Sequence for copy and paste (FileOperation 0)

1. PC copies files: main-channel `NOTI Clipboard` with `ClipboardType "FILE"`,
   `ClipboardResult`, `ClipboardUrl [..]`. The phone puts `file://` items under
   the label `startDoPDrag` (extra `id`) on its clipboard and answers with main
   `NOTI DRAGDROP {DragDropID}`.
2. PC sends KMS common request `InitFileTransfer` (packets 0x64/0x65/0x66,
   JSON) with `FileOperation 0`, `DragDropID`, `TransferID`,
   `FileTransferErrorCodeFromPC`, `FileInfo [{Name, Size}]`. The phone only
   stores it (r2/k.u).
3. User pastes in a DeX-aware app (My Files): the app broadcasts to the DeX app
   with the id and a destination folder; the phone looks up the stored request,
   checks space and answers KMS common response `InitFileTransfer` with a code
   (0 ready, 413 no space, 503 busy), then waits for the files.
4. PC streams each file on the file socket.

Drag and drop is the same with `FileOperation 1`: the phone starts a drag of the
named files at once (KMSService.X) and the drop starts step 3.

## Sockets

- Event (KMS) socket: phone port 30830 (sidesync_packets.EVENT_PORT).
- File socket: phone port 30831 (PC creates one: 0x786f + index), its own
  connection; the phone's FileSocketController handles packets 0x28-0x2a, 0x2f
  and 0x5b on it.

## Packets (version 3, kind, 16-bit big-endian length)

| Kind | Meaning | Body |
| --- | --- | --- |
| 0x28 | file start | 8-byte size (BE); protocol >= 2: 8 more bytes (BE); file name |
| 0x29 | file data | bytes (PC sends 16 KiB chunks) |
| 0x2a | file end | bytes |
| 0x2c / 0x2d | cancel receive / send (event socket) | |
| 0x2e | receiver ready / ready to send (event socket) | |
| 0x2f | transfer finished (file socket) | |
| 0x64-0x66 / 0x67-0x69 | common request / response start, body, end | start: 4-byte id, 8-byte length |

The PC waits up to 2 s for a signal after each chunk.

## Resolved details

- File socket: plain connect to phone port 30831; its handler takes only file
  packets, so no hello is needed there (the event socket keeps its own
  connect-confirmed + heartbeat).
- Start packet: 8-byte size, then (protocol >= 2) an 8-byte data offset for
  resume (0 for a new file), then the name; `\` becomes `/`, so relative paths
  inside folders work. A file arrives only after the phone's InitFileTransfer
  response set its receive folder ("set receive folder first" otherwise).
- Pacing: per file 0x28, 0x29 x n (16 KiB), 0x2a on the file socket; the phone
  then sends 0x2e (receiver ready) on the event socket before the next file.
- Fields the phone reads: FileOperation, DragDropID (copy) or TransferID (drag),
  TransferID, FileTransferErrorCodeFromPC (0; 730/750 are PC-side errors),
  FileInfo[].Name, FileInfo[].Size. ClipboardUrl entries become `file://`
  items named after the files (names only; no PC paths need to leave the PC).
- Paste needs a DeX-aware target app (My Files); it tells the DeX app the
  destination folder.

## Design for this project

The phone pulls at paste time, so file bytes cross client -> gateway -> backend
-> phone only then, streamed with flow control; the small backend never
holds whole files.

## Phone to PC (drag out of the DeX window)

1. A phone app's drag hands the DeX app `START_DRAG` (the files' ClipData).
2. When the pointer leaves the DeX window with the button held, the PC sends IDC
   `SKIN_ACT DRAG_PULL`. If a phone drag of files is running, the phone cancels it
   and answers IDC `SKIN_ACT DRAG_START EVENT <count>` on its own connection to
   the PC's IDC listener; otherwise it injects a cancel.
3. The PC starts a Windows drag; on the drop it sends IDC `SKIN_ACT DRAG_DROP`.
   This client drags a 1-byte placeholder (`phoneFileCopy-<hex>`) so no drop target
   waits for the phone (Explorer asks for the data while hovering), finds the drop
   folder from where the placeholder was copied, then fetches into that folder and
   removes the placeholder. A virtual-file drag (as Outlook drags attachments) was
   tried and did not work live; the placeholder may stay visible for a while.
   While the held drag is outside the picture the client moves the phone pointer one
   step past the edge it crossed (-1, or 1920/1080 in viewer space), so the phone's
   drag rests over nothing instead of an edge element that shows "no drop". The
   official PC app instead clamps to the last edge pixel and sends nothing outside
   (MouseHandler::SendPhoneEvent, PtInRect); the phone injects any coordinate as-is.
4. The phone registers each file with its HTTP server (port chosen at run time)
   and sends KMS `NOTI FILE_SHR` (`SubCmd FILELIST_SHR`) with `FILE_SHR_TIMESTAMP`
   and `Info`, both base64 of AES (session key) text. `Info` holds
   registration ids joined by `/&%/&%`, up to 100 per message:
   `[mime type]http://<phone>:<port>/<encoded path>[?ttl=<title>&fn=<name>&size=<n>]`
   (title and name unencoded); a folder list starts with `!@#$%<parent>`.
5. The PC downloads each path over the tunnel (the body is XORed with 9 unless the
   PC is a Mac), then sends IDC `FILE_SHR_FINISH`
   whose info ends with `,<timestamp>`; the phone then stops serving.

Implemented in phone_files.py and the client's PhoneDrop / DropMarker
(2026-11-11; works live; client 1.0.0). Viewer lines: "DP" pull, "DD"
dropped, "DC" cancelled; back: "DS <count>", "FN <i> <size> <b64 name>",
"FB <b64>", "FE", "FA", "FX <reason>".

Copying files on the phone and pasting on the PC is not supported by the phone's
DeX app (2.5.00.16): its clipboard answer (l2/b.o) returns for URI clips, and the
only sender of its file-list share is the drag-out handler (o2/e.v). Copied rich
content with an image arrives as HTML plus a ClipboardUrl link to the image; this
client pastes its plain text only.
