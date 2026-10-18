package bd.bettingshield.ui;

import android.Manifest;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import bd.bettingshield.R;
import bd.bettingshield.data.BlocklistStore;
import bd.bettingshield.data.Prefs;
import bd.bettingshield.vpn.ShieldVpnService;
import bd.bettingshield.vpn.UpdateJobService;

public class MainActivity extends BaseActivity {

    private static final int REQ_VPN = 100;
    private static final int REQ_NOTIF = 101;

    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable tick = new Runnable() {
        @Override public void run() {
            refresh();
            handler.postDelayed(this, 1500);
        }
    };

    private LinearLayout statusCard;
    private TextView statusTitle;
    private TextView statusText;
    private Button toggle;
    private LinearLayout dnsWarning;
    private TextView statDomains;
    private TextView statUpdated;
    private TextView statBlocked;
    private TextView statDiag;
    private Button strictButton;
    private TextView appsButtonHint;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        BlocklistStore.load(this);
        UpdateJobService.schedule(this);

        LinearLayout p = page(getString(R.string.app_name), false);

        // ---- status card ----
        statusCard = Ui.coloredCard(this, R.color.bad_bg);
        statusTitle = Ui.text(this, "", 24, true, R.color.text);
        statusText = Ui.text(this, "", 15, false, R.color.text);
        statusCard.addView(statusTitle);
        statusCard.addView(statusText, Ui.lp(this, 6));
        toggle = Ui.button(this, "", true, v -> onToggle());
        statusCard.addView(toggle, Ui.lp(this, 14));
        p.addView(statusCard, Ui.lp(this, 12));

        // ---- private DNS warning ----
        dnsWarning = Ui.coloredCard(this, R.color.warn_bg);
        dnsWarning.addView(Ui.text(this, getString(R.string.private_dns_warning), 14, false, R.color.text));
        dnsWarning.addView(Ui.button(this, getString(R.string.open_network_settings), false,
                v -> startActivity(new Intent(Settings.ACTION_WIRELESS_SETTINGS))), Ui.lp(this, 8));
        p.addView(dnsWarning, Ui.lp(this, 12));

        // ---- stats ----
        LinearLayout stats = Ui.card(this);
        statDomains = Ui.text(this, "", 15, false, R.color.text);
        statUpdated = Ui.text(this, "", 15, false, R.color.text);
        statBlocked = Ui.text(this, "", 15, false, R.color.text);
        stats.addView(statDomains);
        stats.addView(statUpdated, Ui.lp(this, 6));
        stats.addView(statBlocked, Ui.lp(this, 6));
        statDiag = Ui.text(this, "", 13, false, R.color.subtext);
        stats.addView(statDiag, Ui.lp(this, 6));
        p.addView(stats, Ui.lp(this, 12));

        // ---- strict mode (experimental) ----
        LinearLayout strictCard = Ui.card(this);
        strictCard.addView(Ui.text(this, getString(R.string.strict_note), 13, false, R.color.subtext));
        strictButton = Ui.button(this, "", false, v -> onStrictToggle());
        strictCard.addView(strictButton, Ui.lp(this, 8));
        p.addView(strictCard, Ui.lp(this, 12));

        // ---- navigation ----
        p.addView(Ui.button(this, getString(R.string.nav_report), true,
                v -> startActivity(new Intent(this, ReportActivity.class))), Ui.lp(this, 16));
        p.addView(Ui.button(this, getString(R.string.nav_blocklist), false,
                v -> startActivity(new Intent(this, BlocklistActivity.class))), Ui.lp(this, 10));
        p.addView(Ui.button(this, getString(R.string.nav_apps), false,
                v -> startActivity(new Intent(this, AppsActivity.class))), Ui.lp(this, 10));
        p.addView(Ui.button(this, getString(R.string.nav_help), false,
                v -> startActivity(new Intent(this, HelpActivity.class))), Ui.lp(this, 10));

        p.addView(Ui.text(this, getString(R.string.honest_note), 13, false, R.color.subtext), Ui.lp(this, 16));

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, REQ_NOTIF);
        }

        // Refresh the list in the background if it has not been checked for a while.
        if (System.currentTimeMillis() - Prefs.lastUpdateCheck(this) > 6L * 60 * 60 * 1000) {
            new Thread(() -> BlocklistStore.update(getApplicationContext(), false)).start();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        handler.post(tick);
    }

    @Override
    protected void onPause() {
        handler.removeCallbacks(tick);
        super.onPause();
    }

    private void refresh() {
        boolean on = ShieldVpnService.isRunning();
        boolean wanted = Prefs.isProtectionWanted(this);
        if (on) {
            statusCard.setBackgroundTintList(null);
            ((android.graphics.drawable.GradientDrawable) statusCard.getBackground())
                    .setColor(getColor(R.color.ok_bg));
            statusTitle.setText(R.string.status_on);
            statusText.setText(R.string.status_on_text);
            toggle.setText(R.string.turn_off);
        } else {
            ((android.graphics.drawable.GradientDrawable) statusCard.getBackground())
                    .setColor(getColor(R.color.bad_bg));
            statusTitle.setText(R.string.status_off);
            statusText.setText(wanted ? R.string.status_off_stopped : R.string.status_off_text);
            toggle.setText(R.string.turn_on);
        }
        dnsWarning.setVisibility(isStrictPrivateDns() ? android.view.View.VISIBLE : android.view.View.GONE);

        statDomains.setText(getString(R.string.stat_domains, BlocklistStore.domainCount()));
        long ok = Prefs.lastUpdateOk(this);
        statUpdated.setText(getString(R.string.stat_updated, ok == 0 ? getString(R.string.seed_only) : formatTime(ok)));
        statBlocked.setText(getString(R.string.stat_blocked, Prefs.totalBlocked(this)));
        statDiag.setText(getString(R.string.stat_diag, ShieldVpnService.statPackets.get(),
                ShieldVpnService.statDns.get(), ShieldVpnService.statOther.get()));
        strictButton.setText(Prefs.isStrictMode(this) ? R.string.strict_btn_on : R.string.strict_btn_off);
    }

    private void onStrictToggle() {
        Prefs.setStrictMode(this, !Prefs.isStrictMode(this));
        if (ShieldVpnService.isRunning()) {
            // Restart the filter so the new setting takes effect.
            ShieldVpnService.stop(this);
            handler.postDelayed(this::startProtection, 1000);
        }
        handler.postDelayed(this::refresh, 1300);
    }

    /** "Private DNS" set to a specific provider hostname bypasses a local DNS filter. */
    private boolean isStrictPrivateDns() {
        try {
            String mode = Settings.Global.getString(getContentResolver(), "private_dns_mode");
            return "hostname".equals(mode);
        } catch (Exception e) {
            return false;
        }
    }

    private void onToggle() {
        if (ShieldVpnService.isRunning()) {
            new AlertDialog.Builder(this)
                    .setTitle(R.string.confirm_off_title)
                    .setMessage(R.string.confirm_off_message)
                    .setNegativeButton(R.string.keep_on, null)
                    .setPositiveButton(R.string.turn_off, (d, w) -> {
                        ShieldVpnService.stop(this);
                        handler.postDelayed(this::refresh, 400);
                    })
                    .show();
            return;
        }
        Intent consent = VpnService.prepare(this);
        if (consent == null) {
            startProtection();
        } else {
            new AlertDialog.Builder(this)
                    .setTitle(R.string.vpn_explain_title)
                    .setMessage(R.string.vpn_explain_message)
                    .setNegativeButton(R.string.cancel, null)
                    .setPositiveButton(R.string.continue_, (d, w) -> startActivityForResult(consent, REQ_VPN))
                    .show();
        }
    }

    private void startProtection() {
        Prefs.setProtectionWanted(this, true);
        ShieldVpnService.start(this);
        handler.postDelayed(this::refresh, 600);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_VPN) {
            if (resultCode == RESULT_OK) startProtection();
            else toast(R.string.vpn_denied);
        }
    }
}
