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
    // The click that activates the window only focuses it: its press and release stay
    // here. activationClickAt is when an activation found a mouse button held.
    private long activationClickAt;
    private bool focusClick;
    private int uiMoves;
    private static readonly TimeSpan ActivationClickWindow = TimeSpan.FromMilliseconds(500);
    private void BackendLostFocus(object sender, RoutedEventArgs args) => ReleaseFocusedInput();
    private void BackendKeyDown(object sender, KeyRoutedEventArgs args)
    {
        if (InputBlocked) return;
        controls.Enabled = session.CanSendInput && windowActive;
        var lines = controls.Key((int)args.KeyStatus.ScanCode, args.KeyStatus.IsExtendedKey, true, (int)args.Key);
        Send(lines); if (lines.Length != 0) args.Handled = true;
    }
    private void BackendKeyUp(object sender, KeyRoutedEventArgs args)
    {
        if (InputBlocked) return;
        var lines = controls.Key((int)args.KeyStatus.ScanCode, args.KeyStatus.IsExtendedKey, false, (int)args.Key);
        Send(lines); if (lines.Length != 0) args.Handled = true;
    }
    private void BackendPointerMoved(object sender, PointerRoutedEventArgs args)
    {
        if (InputBlocked || !session.CanSendInput) return;
        var point = args.GetCurrentPoint(VideoSurface);
        if (recordingInput && ++uiMoves % 10 == 1) MediaTrace($"ui_move active={windowActive} focusClick={focusClick}");
        if (!windowActive || focusClick)
        {
            // Not focused (or the focusing click): the phone still follows the pointer.
            Send(controls.Hover(point.Position.X, point.Position.Y, VideoSurface.ActualWidth, VideoSurface.ActualHeight));
            return;
        }
        controls.Enabled = true;
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
        if (InputBlocked || !session.CanSendInput) return;
        var hit = args.GetCurrentPoint(VideoSurface).Position;
        if (hit.X < 0 || hit.Y < 0 || hit.X >= VideoSurface.ActualWidth || hit.Y >= VideoSurface.ActualHeight) return;
        bool activating = !windowActive
            || (activationClickAt != 0 && Stopwatch.GetElapsedTime(activationClickAt) < ActivationClickWindow);
        activationClickAt = 0;
        if (recordingInput) MediaTrace($"ui_press active={windowActive} activating={activating}");
        if (activating)
        {
            focusClick = true;
            InputSurface.Focus(FocusState.Programmatic);
            args.Handled = true;
            return;
        }
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
        if (focusClick)
        {
            var held = args.GetCurrentPoint(VideoSurface).Properties;
            if (!held.IsLeftButtonPressed && !held.IsRightButtonPressed && !held.IsMiddleButtonPressed) focusClick = false;
            args.Handled = true;
            return;
        }
        dragOutArmed = false; dragOutPoint = null;
        if (InputBlocked) return;
        BackendPointerMoved(sender, args);
        var p = args.GetCurrentPoint(VideoSurface).Properties;
        foreach (var (button, down) in new[] { (1, p.IsLeftButtonPressed), (2, p.IsMiddleButtonPressed),
                  (3, p.IsRightButtonPressed), (4, p.IsXButton1Pressed), (5, p.IsXButton2Pressed) })
            if (!down) Send(controls.Button(button, false));
        if (!controls.HasButtons) VideoSurface.ReleasePointerCapture(args.Pointer); args.Handled = true;
    }
    private void BackendWheel(object sender, PointerRoutedEventArgs args)
    {
        if (InputBlocked || !session.CanSendInput || !windowActive) return;
        BackendPointerMoved(sender, args);
        var p = args.GetCurrentPoint(VideoSurface).Properties;
        Send(controls.Wheel(p.MouseWheelDelta, p.IsHorizontalMouseWheel)); args.Handled = true;
    }
    private void BackendPointerCaptureLost(object sender, PointerRoutedEventArgs args) => Send(controls.ReleaseButtons());
}
