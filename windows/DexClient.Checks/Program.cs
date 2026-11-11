using System.Runtime.InteropServices;
using DexClient.Core;

if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64)
    throw new InvalidOperationException("This acceptance batch requires Windows x64.");

var checks = 0;
void Check(bool condition, string description)
{
    if (!condition) throw new InvalidOperationException(description);
    checks++;
}
var session = new SessionState();
Check(!session.CanSendInput, "Input disabled before connect");
var first = session.BeginConnect();
Check(!session.PictureReady(first), "Picture cannot skip handshake");
Check(session.TransportReady(first), "Transport ready");
Check(!session.TransportReady(first), "Duplicate transport completion ignored");
Check(session.SessionStarted(first), "Session started");
Check(!session.CanSendInput, "Input disabled before picture");
Check(session.PictureReady(first) && session.CanSendInput, "Picture enables input");
Check(session.BeginDisconnect(first) && !session.CanSendInput, "Disconnect disables input immediately");
Check(!session.PictureReady(first), "Late picture cannot undo disconnect");
Check(session.Closed(first), "Close completes disconnect");
var second = session.BeginConnect();
Check(second > first, "Generation advances");
Check(!session.Closed(first) && !session.TransportReady(first), "Old callbacks cannot alter new session");
Check(session.State == ConnectionState.Contacting, "New session preserved");
Check(session.BeginDisconnect(second), "Cancel during startup");
Check(!session.SessionStarted(second), "Cancelled startup ignored");
Check(session.Closed(second), "Cancelled session closes");
var third = session.BeginConnect();
Check(session.Closed(third), "Transport failure closes startup");
Check(!session.Closed(third), "Duplicate close ignored");
session.BeginConnect();
var refused = false;
try { session.BeginConnect(); }
catch (InvalidOperationException) { refused = true; }
Check(refused, "Second connect refused");
var input = new DesktopInput();
Check(input.Move(10, 10, 100, 100).Length == 0, "No pointer before picture");
Check(input.Key(0x1e, false, true).Length == 0, "No key before picture");
input.Enabled = true;
Check(input.Move(50, 25, 100, 50).Single() == "M 0 960 540", "Desktop mapping");
Check(input.Button(1, true).Single() == "M 2 960 540", "Left press mapping");
Check(input.Button(1, true).Length == 0, "Duplicate press suppressed");
Check(input.Key(0x1e, false, true).Single() == "K d 30", "Set-1 A to evdev");
Check(input.Key(0x1e, false, true).Length == 0, "Repeated key suppressed");
Check(input.Key(0x1d, true, true).Single() == "K d 97", "Extended right control");
Check(input.Key(0x5b, true, true).Length == 0, "Windows key remains local");
Check(input.ReleaseButtons().Single() == "M 1 960 540", "Capture loss releases buttons");
Check(input.ReleaseAll().SequenceEqual(new[] { "K u 30", "K u 97" }), "Mouse release preserves held keyboard");
Check(input.ReleaseAll().Length == 0, "Release is idempotent");
input.Key(0x38, false, true);
Check(input.Key(0x3e, false, true).Length == 0, "Alt-F4 stays local");
input.ReleaseAll();
Check(input.Key(0x5b, true, true, 0x5b, system: true).Single() == "K d 125", "Hooked left Windows key to Meta");
Check(input.Key(0x5b, true, false, 0x5b, system: true).Single() == "K u 125", "Hooked Windows key release");
Check(input.Key(0x5c, true, true, 0x5c, system: true).Single() == "K d 126", "Hooked right Windows key");
input.ReleaseAll();
input.Key(0x38, false, true);
Check(input.Key(0x0f, false, true, 0x09, system: true).Single() == "K d 15", "Hooked Alt+Tab reaches the phone");
Check(input.Key(0x3e, false, true, 0x73, system: true).Length == 0, "Alt-F4 stays local even from the hook");
input.ReleaseAll();
Check(DesktopInput.CapturesSystemKey(0x5b, false, false) && DesktopInput.CapturesSystemKey(0x5c, false, false), "Windows keys are captured");
Check(DesktopInput.CapturesSystemKey(0x09, true, false) && !DesktopInput.CapturesSystemKey(0x09, false, false), "Tab captured only with Alt");
Check(DesktopInput.CapturesSystemKey(0x1b, true, false) && DesktopInput.CapturesSystemKey(0x1b, false, true) && !DesktopInput.CapturesSystemKey(0x1b, false, false), "Esc captured only with Alt or Ctrl");
Check(!DesktopInput.CapturesSystemKey(0x73, true, false) && !DesktopInput.CapturesSystemKey(0x2e, true, true) && !DesktopInput.CapturesSystemKey(0x4c, false, false), "Alt+F4, Ctrl+Alt+Del and plain keys stay with Windows");
var clip = new ClipboardSync();
Check(clip.Activated(null) == null && clip.Activated("") == null, "Empty PC clipboard is not shared");
Check(clip.Activated("héllo") == "P " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("héllo")), "PC text becomes a P line");
Check(clip.Activated("héllo") == null, "Unchanged PC text is not resent");
Check(clip.PhoneLine("V " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("from phone"))) == "from phone", "Phone V line decodes");
Check(clip.Activated("from phone") == null, "Phone text is not echoed back to the phone");
Check(clip.PhoneLine("V !!!") == null && clip.PhoneLine("C 1002 0") == null && clip.PhoneLine("V " + Convert.ToBase64String(new byte[] { 0xff, 0xfe })) == null, "Bad phone lines are ignored");
string big = new string('x', ClipboardSync.MaxCharacters + 10);
string? bigLine = clip.Activated(big);
Check(bigLine != null && bigLine.Length <= ClipboardSync.MaxLineLength, "Long PC text is cut to the phone limit");
Check(ClipboardSync.MaxLineLength == 2 + 4 * ((4 * 131072 + 2) / 3), "Line limit matches the backend and gateway");
Check(input.FilePointer(50, 25, 100, 50) == "960 540" && input.FilePointer(-1, 5, 100, 50) == null && input.FilePointer(100, 5, 100, 50) == null, "File drop point maps to the phone input space");
var offer = new FileOffer();
var copied = new[] { (@"C:\x\a.txt", "a.txt", 5L), (@"C:\x\b.bin", "b.bin", 0L) };
string? offerLine = offer.Offer(FileOffer.Copy, copied);
Check(offerLine == "FO 0 " + Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("[[\"a.txt\",5],[\"b.bin\",0]]")), "Copied files become an FO 0 line with names only");
Check(offer.Offer(FileOffer.Copy, copied) == null, "Same copied files are not offered twice");
Check(offer.Offer(FileOffer.Copy, copied, "7") != null && offer.Offer(FileOffer.Copy, copied, "7") == null && offer.Offer(FileOffer.Copy, copied, "8") != null, "A new copy of the same files is offered again; refocusing is not");
var progressOffer = new FileOffer();
progressOffer.Offer(FileOffer.Drag, new[] { ("p1", "a", 100000L), ("p2", "b", 0L), ("p3", "c", 10L) });
Check(progressOffer.Delivered("S 0 49152 0") == (49152L, 100010L, false, 0), "Delivery progress counts bytes the phone accepted");
Check(progressOffer.Delivered("S 2 10 1") == (100010L, 100010L, true, 2) && progressOffer.Delivered("S 0 100000 1")?.Finished == false, "Only the last file's end finishes the transfer");
Check(progressOffer.Delivered("S 0 100001 0") == null && progressOffer.Delivered("S 3 0 1") == null && progressOffer.Delivered("G 0 1") == null, "Bad progress lines are ignored");
Check(offer.Offer(FileOffer.Drag, copied)?.StartsWith("FO 1 ") == true, "Dropped files are always offered");
Check(offer.Offer(FileOffer.Copy, new[] { (@"C:\x", "..", 1L) }) == null && !FileOffer.IsPlainName("a/b") && !FileOffer.IsPlainName(""), "Bad names are not offered");
Check(FileOffer.TryParseRequest("G 2 7", out int gFile, out long gChunk) && gFile == 2 && gChunk == 7 && !FileOffer.TryParseRequest("G 2", out _, out _) && !FileOffer.TryParseRequest("C 1002 0", out _, out _), "Chunk requests parse");
Check(FileOffer.ChunkLine(new byte[FileOffer.ChunkBytes]).Length == FileOffer.MaxChunkLine && FileOffer.MaxChunkLine == 2 + 4 * ((49152 + 2) / 3), "Chunk line limit matches the backend");
Check(input.Wheel(-120, false).Single() == "M 8 960 540", "Vertical wheel");
Check(input.Wheel(120, true).Single() == "M 11 960 540", "Horizontal wheel");
Check(input.Key(0x45, false, true, 0x13).Single() == "K d 119", "Pause mapping");
Check(input.Key(0, false, true, 0x7c).Single() == "K d 183", "F13 mapping");
Check(input.Key(0, false, true, 0x87).Single() == "K d 194", "F24 mapping");
Check(input.Key(0, false, true, 0xad).Single() == "K d 113", "Mute mapping");
Check(input.Key(0, false, true, 0xae).Single() == "K d 114", "Volume down mapping");
Check(input.Key(0, false, true, 0xaf).Single() == "K d 115", "Volume up mapping");
input.ReleaseAll();
long ticks = 0;
var motion = new DesktopInput(() => ticks) { Enabled = true };
Check(motion.Move(1, 1, 100, 100).Length == 1, "First move immediate");
Check(motion.Move(2, 2, 100, 100).Length == 0 && motion.Move(3, 3, 100, 100).Length == 0, "Pointer burst throttled");
ticks += System.Diagnostics.Stopwatch.Frequency / 30;
Check(motion.FlushMove().Single() == "M 0 57 32", "Newest pointer position eventually flushed");
motion.Move(4, 4, 100, 100);
Check(motion.Wheel(120, false).SequenceEqual(new[] { "M 0 76 43", "M 7 76 43" }), "Wheel flushes pending move first");
Check(input.Key(0x70, false, true, 0x15).Single() == "K d 93", "Japanese Kana is not confused with Hangul");
input.ReleaseAll();
foreach (var pair in new[] { (0x59,117), (0x73,89), (0x79,92), (0x7b,94), (0x7d,124), (0x7e,121) })
{ Check(input.Key(pair.Item1, false, true).Single() == $"K d {pair.Item2}", "International/keypad mapping"); input.ReleaseAll(); }
Check(input.Key(0xf2, false, true, 0x15).Single() == "K d 122", "Hangul mapping"); input.ReleaseAll();
Check(input.Key(0xf1, false, true, 0x19).Single() == "K d 123", "Hanja mapping"); input.ReleaseAll();
Check(input.Move(double.NaN, 0, 100, 100).Length == 0, "Invalid pointer coordinate ignored");
// Every saved Python HID usage has a matching native event mapping when Windows
// delivers it. Meta keys deliberately stay local in both default clients.
foreach (var entry in new (int Scan, bool Extended, int Virtual, int Evdev)[] {
    (30, false, 0, 30), // HID04
    (48, false, 0, 48), // HID05
    (46, false, 0, 46), // HID06
    (32, false, 0, 32), // HID07
    (18, false, 0, 18), // HID08
    (33, false, 0, 33), // HID09
    (34, false, 0, 34), // HID0a
    (35, false, 0, 35), // HID0b
    (23, false, 0, 23), // HID0c
    (36, false, 0, 36), // HID0d
    (37, false, 0, 37), // HID0e
    (38, false, 0, 38), // HID0f
    (50, false, 0, 50), // HID10
    (49, false, 0, 49), // HID11
    (24, false, 0, 24), // HID12
    (25, false, 0, 25), // HID13
    (16, false, 0, 16), // HID14
    (19, false, 0, 19), // HID15
    (31, false, 0, 31), // HID16
    (20, false, 0, 20), // HID17
    (22, false, 0, 22), // HID18
    (47, false, 0, 47), // HID19
    (17, false, 0, 17), // HID1a
    (45, false, 0, 45), // HID1b
    (21, false, 0, 21), // HID1c
    (44, false, 0, 44), // HID1d
    (2, false, 0, 2), // HID1e
    (3, false, 0, 3), // HID1f
    (4, false, 0, 4), // HID20
    (5, false, 0, 5), // HID21
    (6, false, 0, 6), // HID22
    (7, false, 0, 7), // HID23
    (8, false, 0, 8), // HID24
    (9, false, 0, 9), // HID25
    (10, false, 0, 10), // HID26
    (11, false, 0, 11), // HID27
    (28, false, 0, 28), // HID28
    (1, false, 0, 1), // HID29
    (14, false, 0, 14), // HID2a
    (15, false, 0, 15), // HID2b
    (57, false, 0, 57), // HID2c
    (12, false, 0, 12), // HID2d
    (13, false, 0, 13), // HID2e
    (26, false, 0, 26), // HID2f
    (27, false, 0, 27), // HID30
    (43, false, 0, 43), // HID31
    (43, false, 0, 43), // HID32
    (39, false, 0, 39), // HID33
    (40, false, 0, 40), // HID34
    (41, false, 0, 41), // HID35
    (51, false, 0, 51), // HID36
    (52, false, 0, 52), // HID37
    (53, false, 0, 53), // HID38
    (58, false, 0, 58), // HID39
    (59, false, 0, 59), // HID3a
    (60, false, 0, 60), // HID3b
    (61, false, 0, 61), // HID3c
    (62, false, 0, 62), // HID3d
    (63, false, 0, 63), // HID3e
    (64, false, 0, 64), // HID3f
    (65, false, 0, 65), // HID40
    (66, false, 0, 66), // HID41
    (67, false, 0, 67), // HID42
    (68, false, 0, 68), // HID43
    (87, false, 0, 87), // HID44
    (88, false, 0, 88), // HID45
    (55, true, 0, 99), // HID46
    (70, false, 0, 70), // HID47
    (69, false, 19, 119), // HID48
    (82, true, 0, 110), // HID49
    (71, true, 0, 102), // HID4a
    (73, true, 0, 104), // HID4b
    (83, true, 0, 111), // HID4c
    (79, true, 0, 107), // HID4d
    (81, true, 0, 109), // HID4e
    (77, true, 0, 106), // HID4f
    (75, true, 0, 105), // HID50
    (80, true, 0, 108), // HID51
    (72, true, 0, 103), // HID52
    (69, false, 0, 69), // HID53
    (53, true, 0, 98), // HID54
    (55, false, 0, 55), // HID55
    (74, false, 0, 74), // HID56
    (78, false, 0, 78), // HID57
    (28, true, 0, 96), // HID58
    (79, false, 0, 79), // HID59
    (80, false, 0, 80), // HID5a
    (81, false, 0, 81), // HID5b
    (75, false, 0, 75), // HID5c
    (76, false, 0, 76), // HID5d
    (77, false, 0, 77), // HID5e
    (71, false, 0, 71), // HID5f
    (72, false, 0, 72), // HID60
    (73, false, 0, 73), // HID61
    (82, false, 0, 82), // HID62
    (83, false, 0, 83), // HID63
    (86, false, 0, 86), // HID64
    (93, true, 0, 127), // HID65
    (94, true, 0, 116), // HID66
    (89, false, 0, 117), // HID67
    (0, false, 124, 183), // HID68
    (0, false, 125, 184), // HID69
    (0, false, 126, 185), // HID6a
    (0, false, 127, 186), // HID6b
    (0, false, 128, 187), // HID6c
    (0, false, 129, 188), // HID6d
    (0, false, 130, 189), // HID6e
    (0, false, 131, 190), // HID6f
    (0, false, 132, 191), // HID70
    (0, false, 133, 192), // HID71
    (0, false, 134, 193), // HID72
    (0, false, 135, 194), // HID73
    (0, false, 173, 113), // HID7f
    (0, false, 175, 115), // HID80
    (0, false, 174, 114), // HID81
    (126, false, 0, 121), // HID85
    (115, false, 0, 89), // HID87
    (112, false, 21, 93), // HID88
    (125, false, 0, 124), // HID89
    (121, false, 0, 92), // HID8a
    (123, false, 0, 94), // HID8b
    (242, false, 21, 122), // HID90
    (241, false, 25, 123), // HID91
    (29, false, 0, 29), // HIDe0
    (42, false, 0, 42), // HIDe1
    (56, false, 0, 56), // HIDe2
    (91, true, 0, 125), // HIDe3
    (29, true, 0, 97), // HIDe4
    (54, false, 0, 54), // HIDe5
    (56, true, 0, 100), // HIDe6
    (92, true, 0, 126), // HIDe7
})
{
    input.Enabled = true;
    var lines = input.Key(entry.Scan, entry.Extended, true, entry.Virtual);
    Check(entry.Evdev is 125 or 126 ? lines.Length == 0 : lines.SequenceEqual(new[] { $"K d {entry.Evdev}" }), "Python HID/native event mapping parity");
    input.ReleaseAll();
}
Check(input.Key(0x45, true, true, 0x90).Single() == "K d 69", "Legacy extended Num Lock"); input.ReleaseAll();
Check(input.Key(0x54, false, true, 0x2c).Single() == "K d 99", "Alt-PrintScreen scan variant"); input.ReleaseAll();
Check(input.Key(0x72, false, false, 0x15).SequenceEqual(new[] { "K d 122", "K u 122" }), "Release-only Korean Hangul tap");
Check(input.Key(0x71, false, false, 0x19).SequenceEqual(new[] { "K d 123", "K u 123" }), "Release-only Korean Hanja tap");
Check(input.ReleaseAll().Length == 0, "Release-only language key leaves nothing held");
Console.WriteLine($"PASS: {checks} session state checks; OS={RuntimeInformation.OSDescription}; architecture={RuntimeInformation.ProcessArchitecture}");
