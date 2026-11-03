package app.blackscreen;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.view.View;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.view.WindowManager;

/**
 * Full-screen black on the phone screen with the status and navigation bars hidden (immersive),
 * so no static pixels stay lit. An edge swipe shows the bars only briefly. Touches and Back do
 * nothing. BlackScreenService's overlay stays underneath as a backstop if this is ever left.
 *
 * Start: am start --display 0 -n app.blackscreen/.BlackActivity
 * Stop:  am force-stop app.blackscreen (also removes the overlay)
 */
public class BlackActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        WindowManager.LayoutParams params = getWindow().getAttributes();
        params.layoutInDisplayCutoutMode = WindowManager.LayoutParams.LAYOUT_IN_DISPLAY_CUTOUT_MODE_ALWAYS;
        params.screenBrightness = 0f;
        getWindow().setAttributes(params);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        getWindow().setDecorFitsSystemWindows(false);
        setShowWhenLocked(true);
        View black = new View(this);
        black.setBackgroundColor(Color.BLACK);
        black.setOnTouchListener((view, event) -> true);
        setContentView(black);
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        hideBars();
    }

    @Override
    protected void onResume() {
        super.onResume();
        hideBars();
    }

    private void hideBars() {
        WindowInsetsController controller = getWindow().getInsetsController();
        if (controller != null) {
            controller.setSystemBarsBehavior(WindowInsetsController.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE);
            controller.hide(WindowInsets.Type.systemBars());
        }
    }

    @Override
    @SuppressWarnings("deprecation")
    public void onBackPressed() {
        // Back does nothing: the phone screen stays covered.
    }
}
