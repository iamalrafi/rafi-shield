package bd.bettingshield.ui;

import android.app.Activity;
import android.content.Context;
import android.content.res.Configuration;
import android.view.View;
import android.view.WindowInsets;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import bd.bettingshield.R;
import bd.bettingshield.data.Prefs;
import java.util.Locale;

/** Common screen frame: scrolling page, title, language, and spacing for system bars. */
abstract class BaseActivity extends Activity {

    @Override
    protected void attachBaseContext(Context base) {
        String lang = Prefs.language(base);
        Configuration cfg = new Configuration(base.getResources().getConfiguration());
        Locale locale = new Locale(lang);
        Locale.setDefault(locale);
        cfg.setLocale(locale);
        super.attachBaseContext(base.createConfigurationContext(cfg));
    }

    /** Builds the empty page and returns the vertical container to add views into. */
    @SuppressWarnings("deprecation")
    protected LinearLayout page(String title, boolean showBack) {
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(getColor(R.color.bg));

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int side = Ui.dp(this, 16);
        content.setPadding(side, Ui.dp(this, 12), side, Ui.dp(this, 24));
        scroll.addView(content, new ScrollView.LayoutParams(
                ScrollView.LayoutParams.MATCH_PARENT, ScrollView.LayoutParams.WRAP_CONTENT));

        // Android 15 draws apps edge-to-edge: keep content clear of the status/navigation bars.
        scroll.setOnApplyWindowInsetsListener((View v, WindowInsets insets) -> {
            v.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                    insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets;
        });

        if (showBack) {
            TextView back = Ui.text(this, "←  " + getString(R.string.back), 16, true, R.color.primary);
            back.setPadding(0, Ui.dp(this, 8), 0, Ui.dp(this, 8));
            back.setOnClickListener(v -> finish());
            content.addView(back);
        }
        TextView t = Ui.text(this, title, 26, true, R.color.text);
        content.addView(t, Ui.lp(this, 4));

        setContentView(scroll);
        return content;
    }

    protected void toast(int resId) {
        android.widget.Toast.makeText(this, resId, android.widget.Toast.LENGTH_LONG).show();
    }

    protected void toast(String s) {
        android.widget.Toast.makeText(this, s, android.widget.Toast.LENGTH_LONG).show();
    }

    protected String formatTime(long ms) {
        if (ms <= 0) return getString(R.string.never);
        return new java.text.SimpleDateFormat("d MMM yyyy, HH:mm", Locale.getDefault())
                .format(new java.util.Date(ms));
    }
}
