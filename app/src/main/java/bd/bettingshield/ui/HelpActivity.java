package bd.bettingshield.ui;

import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.widget.LinearLayout;
import bd.bettingshield.BuildConfig;
import bd.bettingshield.R;
import bd.bettingshield.data.Prefs;

/** Settings, troubleshooting, privacy and an honest explanation of what the app cannot do. */
public class HelpActivity extends BaseActivity {

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout p = page(getString(R.string.help_title), true);

        // Language
        boolean bn = "bn".equals(Prefs.language(this));
        p.addView(Ui.button(this, getString(bn ? R.string.switch_to_english : R.string.switch_to_bangla), false, v -> {
            Prefs.setLanguage(this, bn ? "en" : "bn");
            Intent i = new Intent(this, MainActivity.class);
            i.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK | Intent.FLAG_ACTIVITY_NEW_TASK);
            startActivity(i);
        }), Ui.lp(this, 12));

        section(p, R.string.help_restore_title, R.string.help_restore_body);
        p.addView(Ui.button(this, getString(R.string.open_vpn_settings), false,
                v -> startActivity(new Intent(Settings.ACTION_VPN_SETTINGS))), Ui.lp(this, 8));

        section(p, R.string.help_battery_title, R.string.help_battery_body);
        p.addView(Ui.button(this, getString(R.string.open_battery_settings), false,
                v -> startActivity(new Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))), Ui.lp(this, 8));
        p.addView(Ui.button(this, getString(R.string.open_app_settings), false, v -> {
            Intent i = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
            i.setData(android.net.Uri.parse("package:" + getPackageName()));
            startActivity(i);
        }), Ui.lp(this, 8));

        section(p, R.string.help_dns_title, R.string.help_dns_body);
        section(p, R.string.help_limits_title, R.string.help_limits_body);
        section(p, R.string.help_permissions_title, R.string.help_permissions_body);
        section(p, R.string.help_privacy_title, R.string.help_privacy_body);
        section(p, R.string.help_help_title, R.string.help_help_body);

        p.addView(Ui.text(this, getString(R.string.version_line, BuildConfig.VERSION_NAME),
                12, false, R.color.subtext), Ui.lp(this, 20));
    }

    private void section(LinearLayout p, int titleRes, int bodyRes) {
        LinearLayout card = Ui.card(this);
        card.addView(Ui.text(this, getString(titleRes), 17, true, R.color.text));
        card.addView(Ui.text(this, getString(bodyRes), 14, false, R.color.text), Ui.lp(this, 6));
        p.addView(card, Ui.lp(this, 14));
    }
}
