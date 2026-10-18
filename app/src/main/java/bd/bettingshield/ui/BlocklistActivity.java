package bd.bettingshield.ui;

import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.TextView;
import bd.bettingshield.BuildConfig;
import bd.bettingshield.R;
import bd.bettingshield.data.BlockLog;
import bd.bettingshield.data.BlocklistStore;
import bd.bettingshield.data.Prefs;
import java.util.List;

/** Blocklist details, manual update, and the list of recently blocked domains. */
public class BlocklistActivity extends BaseActivity {

    private TextView info;
    private TextView updateResult;
    private LinearLayout logBox;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        BlocklistStore.load(this);
        LinearLayout p = page(getString(R.string.blocklist_title), true);

        LinearLayout card = Ui.card(this);
        info = Ui.text(this, "", 15, false, R.color.text);
        card.addView(info);
        p.addView(card, Ui.lp(this, 12));

        p.addView(Ui.button(this, getString(R.string.update_now), true, v -> updateNow()), Ui.lp(this, 12));
        updateResult = Ui.text(this, "", 14, true, R.color.text);
        p.addView(updateResult, Ui.lp(this, 8));

        p.addView(Ui.text(this, getString(R.string.blocklist_source_info), 13, false, R.color.subtext), Ui.lp(this, 8));

        p.addView(Ui.text(this, getString(R.string.recent_blocked), 18, true, R.color.text), Ui.lp(this, 20));
        p.addView(Ui.text(this, getString(R.string.recent_blocked_hint), 13, false, R.color.subtext), Ui.lp(this, 2));
        logBox = new LinearLayout(this);
        logBox.setOrientation(LinearLayout.VERTICAL);
        p.addView(logBox, Ui.lp(this, 6));
        p.addView(Ui.button(this, getString(R.string.clear_log), false, v -> {
            BlockLog.clear(this);
            showLog();
        }), Ui.lp(this, 10));
    }

    @Override
    protected void onResume() {
        super.onResume();
        showInfo();
        showLog();
    }

    private void showInfo() {
        long ok = Prefs.lastUpdateOk(this);
        long check = Prefs.lastUpdateCheck(this);
        String msg = Prefs.lastUpdateMessage(this);
        StringBuilder sb = new StringBuilder();
        sb.append(getString(R.string.stat_domains, BlocklistStore.domainCount())).append('\n');
        sb.append(getString(R.string.stat_updated, ok == 0 ? getString(R.string.seed_only) : formatTime(ok))).append('\n');
        sb.append(getString(R.string.last_check, formatTime(check)));
        if (!msg.isEmpty()) sb.append(" (").append(msg).append(')');
        sb.append('\n');
        sb.append(BlocklistStore.signaturesEnforced(this)
                ? getString(R.string.signature_on) : getString(R.string.signature_off));
        sb.append('\n');
        sb.append(getString(R.string.bundled_apps_count, BlocklistStore.bettingAppPackages().size()));
        if (BuildConfig.BLOCKLIST_BASE.contains("YOUR_GITHUB_NAME")) {
            sb.append("\n\n").append(getString(R.string.update_not_configured));
        }
        info.setText(sb.toString());
    }

    private void updateNow() {
        updateResult.setText(R.string.working);
        new Thread(() -> {
            BlocklistStore.Result r = BlocklistStore.update(getApplicationContext(), true);
            runOnUiThread(() -> {
                if (isFinishing()) return;
                switch (r.status) {
                    case UPDATED: updateResult.setText(getString(R.string.update_ok, r.message)); break;
                    case UNCHANGED: updateResult.setText(R.string.update_unchanged); break;
                    case NOT_CONFIGURED: updateResult.setText(R.string.update_not_configured); break;
                    default: updateResult.setText(getString(R.string.update_failed, r.message)); break;
                }
                showInfo();
            });
        }).start();
    }

    private void showLog() {
        logBox.removeAllViews();
        List<BlockLog.Entry> list = BlockLog.read(this);
        if (list.isEmpty()) {
            logBox.addView(Ui.text(this, getString(R.string.recent_none), 14, false, R.color.subtext));
            return;
        }
        for (BlockLog.Entry e : list) {
            LinearLayout row = Ui.card(this);
            row.addView(Ui.text(this, e.domain, 16, true, R.color.text));
            row.addView(Ui.text(this, formatTime(e.time), 12, false, R.color.subtext));
            row.setOnClickListener(v -> details(e));
            logBox.addView(row, Ui.lp(this, 8));
        }
    }

    /** "Blocked website information": why was it blocked, plus a way to report a mistake. */
    private void details(BlockLog.Entry e) {
        new AlertDialog.Builder(this)
                .setTitle(e.domain)
                .setMessage(getString(R.string.blocked_details, e.domain, e.matchedEntry))
                .setNegativeButton(R.string.close, null)
                .setPositiveButton(R.string.report_false_positive, (d, w) -> {
                    Intent i = new Intent(this, ReportActivity.class);
                    i.putExtra(ReportActivity.EXTRA_DOMAIN, e.domain);
                    i.putExtra(ReportActivity.EXTRA_FALSE_POSITIVE, true);
                    startActivity(i);
                })
                .show();
    }
}
