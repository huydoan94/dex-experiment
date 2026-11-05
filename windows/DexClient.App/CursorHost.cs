using DexClient.Media;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml.Controls;

namespace DexClient.App;

// The input surface over the phone picture. UIElement.ProtectedCursor can only be
// set from a subclass; this one shows the phone's current pointer shape locally,
// so the Windows pointer changes (arrow, hand, text, resize, ...) without delay.
public sealed partial class CursorHost : ContentControl
{
    public CursorKind Shape { get; private set; } = CursorKind.Arrow;
    public void SetShape(CursorKind kind)
    {
        if (kind == Shape && ProtectedCursor != null) return;
        Shape = kind;
        ProtectedCursor = InputSystemCursor.Create(kind switch
        {
            CursorKind.Hand => InputSystemCursorShape.Hand,
            CursorKind.Help => InputSystemCursorShape.Help,
            CursorKind.Wait => InputSystemCursorShape.Wait,
            CursorKind.Cross => InputSystemCursorShape.Cross,
            CursorKind.IBeam => InputSystemCursorShape.IBeam,
            CursorKind.No => InputSystemCursorShape.UniversalNo,
            CursorKind.SizeAll => InputSystemCursorShape.SizeAll,
            CursorKind.SizeWestEast => InputSystemCursorShape.SizeWestEast,
            CursorKind.SizeNorthSouth => InputSystemCursorShape.SizeNorthSouth,
            CursorKind.SizeNortheastSouthwest => InputSystemCursorShape.SizeNortheastSouthwest,
            CursorKind.SizeNorthwestSoutheast => InputSystemCursorShape.SizeNorthwestSoutheast,
            _ => InputSystemCursorShape.Arrow,
        });
    }
}
