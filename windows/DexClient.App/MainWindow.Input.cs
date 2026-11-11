using System.Diagnostics;
using System.Text.Json;
using DexClient.Core;
using DexClient.Media;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Input;

namespace DexClient.App;

public sealed partial class MainWindow
{
    private void BackendLostFocus(object sender, RoutedEventArgs args) => ReleaseFocusedInput();
    private void BackendKeyDown(object sender, KeyRoutedEventArgs args)
    {
        if (syntheticLive || phoneAcceptance) return;
        controls.Enabled = session.CanSendInput && windowActive;
        var lines = controls.Key((int)args.KeyStatus.ScanCode, args.KeyStatus.IsExtendedKey, true, (int)args.Key);
        Send(lines); if (lines.Length != 0) args.Handled = true;
    }
    private void BackendKeyUp(object sender, KeyRoutedEventArgs args)
    {
        if (syntheticLive || phoneAcceptance) return;
        var lines = controls.Key((int)args.KeyStatus.ScanCode, args.KeyStatus.IsExtendedKey, false, (int)args.Key);
        Send(lines); if (lines.Length != 0) args.Handled = true;
    }
    private void BackendPointerMoved(object sender, PointerRoutedEventArgs args)
    {
        if (syntheticLive || phoneAcceptance || !session.CanSendInput || !windowActive) return;
        controls.Enabled = true;
        var point = args.GetCurrentPoint(VideoSurface);
        if (CursorButton.IsChecked == true)
        {
            var hostPoint = args.GetCurrentPoint(VideoHost).Position;
            CursorPosition.X = hostPoint.X; CursorPosition.Y = hostPoint.Y;
            CursorIndicator.Visibility = Visibility.Visible;
        }
        Send(controls.Move(point.Position.X, point.Position.Y, VideoSurface.ActualWidth, VideoSurface.ActualHeight));
        WatchDragOut(point);
    }
    private void BackendPointerPressed(object sender, PointerRoutedEventArgs args)
    {
        if (syntheticLive || phoneAcceptance || !session.CanSendInput || !windowActive) return;
        var hit = args.GetCurrentPoint(VideoSurface).Position;
        if (hit.X < 0 || hit.Y < 0 || hit.X >= VideoSurface.ActualWidth || hit.Y >= VideoSurface.ActualHeight) return;
        InputSurface.Focus(FocusState.Programmatic);
        BackendPointerMoved(sender, args);
        var p = args.GetCurrentPoint(VideoSurface).Properties;
        foreach (var (button, down) in new[] { (1, p.IsLeftButtonPressed), (2, p.IsMiddleButtonPressed),
                  (3, p.IsRightButtonPressed), (4, p.IsXButton1Pressed), (5, p.IsXButton2Pressed) })
            if (down) Send(controls.Button(button, true));
        VideoSurface.CapturePointer(args.Pointer); args.Handled = true;
    }
    private void BackendPointerReleased(object sender, PointerRoutedEventArgs args)
    {
        dragOutArmed = false; dragOutPoint = null;
        if (syntheticLive || phoneAcceptance) return;
        BackendPointerMoved(sender, args);
        var p = args.GetCurrentPoint(VideoSurface).Properties;
        foreach (var (button, down) in new[] { (1, p.IsLeftButtonPressed), (2, p.IsMiddleButtonPressed),
                  (3, p.IsRightButtonPressed), (4, p.IsXButton1Pressed), (5, p.IsXButton2Pressed) })
            if (!down) Send(controls.Button(button, false));
        if (!controls.HasButtons) VideoSurface.ReleasePointerCapture(args.Pointer); args.Handled = true;
    }
    private void BackendWheel(object sender, PointerRoutedEventArgs args)
    {
        if (syntheticLive || phoneAcceptance || !session.CanSendInput || !windowActive) return;
        BackendPointerMoved(sender, args);
        var p = args.GetCurrentPoint(VideoSurface).Properties;
        Send(controls.Wheel(p.MouseWheelDelta, p.IsHorizontalMouseWheel)); args.Handled = true;
    }
    private void BackendPointerCaptureLost(object sender, PointerRoutedEventArgs args) => Send(controls.ReleaseButtons());
}
