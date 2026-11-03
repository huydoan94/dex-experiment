package app.blackscreen;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.PixelFormat;
import android.hardware.display.DisplayManager;
import android.os.IBinder;
import android.provider.Settings;
import android.util.Log;
import android.view.Display;
import android.view.View;
import android.view.WindowManager;

/**
 * Covers the phone's own screen (display 0) with pure black while a DeX for PC session runs.
 *
 * Black pixels are off on OLED. The window keeps the screen on, so the phone never times out
 * or locks, and it consumes every touch, so nothing on the phone can be used underneath. Input
 * from the PC goes to the DeX display and never reaches this window.
 *
 * Start: am start-foreground-service -n app.blackscreen/.BlackScreenService
 * Stop:  am startservice -n app.blackscreen/.BlackScreenService -a app.blackscreen.STOP
 * BlackActivity hides the system bars on top of this; am force-stop removes both.
 */
public class BlackScreenService extends Service {
    private static final String TAG = "DexBlackScreen";
    private static final String ACTION_STOP = "app.blackscreen.STOP";
    private static final String CHANNEL = "black_screen";
    private static final int NOTIFICATION_ID = 1;

    private WindowManager windowManager;
    private View cover;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTIFICATION_ID, notification());
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopSelf();
            return START_NOT_STICKY;
        }
        if (cover == null && !show()) {
            stopSelf();
        }
        // Not restarted after a kill: a stale black screen must never come back on its own.
        return START_NOT_STICKY;
    }

    private boolean show() {
        if (!Settings.canDrawOverlays(this)) {
            Log.w(TAG, "no SYSTEM_ALERT_WINDOW permission; nothing shown");
            return false;
        }
        Display phone = getSystemService(DisplayManager.class).getDisplay(Display.DEFAULT_DISPLAY);
        if (phone == null) {
            Log.w(TAG, "no default display");
            return false;
        }
        Context window = createWindowContext(phone, WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY, null);
        windowManager = window.getSystemService(WindowManager.class);
        WindowManager.LayoutParams params = new WindowManager.LayoutParams(
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.MATCH_PARENT,
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY,
                // Keep the screen on (no timeout, no lock); no keys taken; cover the whole panel.
                WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
                        | WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE
                        | WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN
                        | WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
                PixelFormat.OPAQUE);
        params.layoutInDisplayCutoutMode = WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
        // Do not shrink around the status and navigation bars: cover the whole panel.
        params.setFitInsetsTypes(0);
        params.screenBrightness = 0f;
        params.setTitle("DexBlackScreen");
        cover = new View(window);
        cover.setBackgroundColor(Color.BLACK);
        // Every touch on the phone screen ends here.
        cover.setOnTouchListener((view, event) -> true);
        windowManager.addView(cover, params);
        Log.i(TAG, "black screen shown");
        return true;
    }

    @Override
    public void onDestroy() {
        if (cover != null) {
            windowManager.removeView(cover);
            cover = null;
            Log.i(TAG, "black screen removed");
        }
        super.onDestroy();
    }

    private Notification notification() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL, "Black screen",
                NotificationManager.IMPORTANCE_MIN));
        return new Notification.Builder(this, CHANNEL)
                .setContentTitle("DeX black screen")
                .setContentText("Phone screen covered for DeX for PC")
                .setSmallIcon(android.R.drawable.ic_lock_idle_lock)
                .setOngoing(true)
                .build();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
