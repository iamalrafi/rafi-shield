package bd.bettingshield.ui;

import android.os.Bundle;
import android.text.InputType;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import bd.bettingshield.R;
import bd.bettingshield.core.DomainUtil;
import bd.bettingshield.data.BlocklistStore;
import bd.bettingshield.data.ReportClient;
import java.util.List;

/** Report a new betting site, or a site that was blocked by mistake, and follow its status. */
public class ReportActivity extends BaseActivity {

    public static final String EXTRA_DOMAIN = "domain";
    public static final String EXTRA_FALSE_POSITIVE = "false_positive";

    private EditText urlInput;
    private EditText noteInput;
    private RadioButton kindBetting;
    private RadioButton kindFalsePositive;
    private TextView result;
    private LinearLayout myReports;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        LinearLayout p = page(getString(R.string.report_title), true);

        p.addView(Ui.text(this, getString(R.string.report_intro), 15, false, R.color.subtext), Ui.lp(this, 6));

        RadioGroup kinds = new RadioGroup(this);
        kindBetting = new RadioButton(this);
        kindBetting.setText(R.string.report_kind_betting);
        kindBetting.setId(android.view.View.generateViewId());
        kindFalsePositive = new RadioButton(this);
        kindFalsePositive.setText(R.string.report_kind_false);
        kindFalsePositive.setId(android.view.View.generateViewId());
        kinds.addView(kindBetting);
        kinds.addView(kindFalsePositive);
        boolean fp = getIntent().getBooleanExtra(EXTRA_FALSE_POSITIVE, false);
        (fp ? kindFalsePositive : kindBetting).setChecked(true);
        p.addView(kinds, Ui.lp(this, 12));

        urlInput = new EditText(this);
        urlInput.setHint(R.string.report_url_hint);
        urlInput.setSingleLine(true);
        urlInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        String pre = getIntent().getStringExtra(EXTRA_DOMAIN);
        if (pre != null) urlInput.setText(pre);
        p.addView(urlInput, Ui.lp(this, 8));

        noteInput = new EditText(this);
        noteInput.setHint(R.string.report_note_hint);
        noteInput.setSingleLine(true);
        noteInput.setFilters(new android.text.InputFilter[]{new android.text.InputFilter.LengthFilter(200)});
        p.addView(noteInput, Ui.lp(this, 4));

        p.addView(Ui.text(this, getString(R.string.report_privacy), 13, false, R.color.subtext), Ui.lp(this, 8));

        p.addView(Ui.button(this, getString(R.string.report_submit), true, v -> submit()), Ui.lp(this, 12));

        result = Ui.text(this, "", 15, true, R.color.text);
        p.addView(result, Ui.lp(this, 10));

        if (!ReportClient.isConfigured()) {
            LinearLayout w = Ui.coloredCard(this, R.color.warn_bg);
            w.addView(Ui.text(this, getString(R.string.report_not_configured), 14, false, R.color.text));
            p.addView(w, Ui.lp(this, 10));
        }

        p.addView(Ui.text(this, getString(R.string.report_mine), 18, true, R.color.text), Ui.lp(this, 20));
        myReports = new LinearLayout(this);
        myReports.setOrientation(LinearLayout.VERTICAL);
        p.addView(myReports, Ui.lp(this, 6));
        p.addView(Ui.button(this, getString(R.string.report_refresh), false, v -> refreshStatuses()), Ui.lp(this, 10));
        showMine();
        if (ReportClient.isConfigured()) refreshStatuses();
    }

    private void submit() {
        String raw = urlInput.getText().toString();
        String host = DomainUtil.normalizeHost(raw);
        if (host == null) {
            result.setText(R.string.report_invalid);
            return;
        }
        boolean falsePositive = kindFalsePositive.isChecked();
        if (DomainUtil.isProtected(host) && !falsePositive) {
            result.setText(R.string.report_protected);
            return;
        }
        if (!falsePositive && BlocklistStore.MATCHER.match(host) != null) {
            result.setText(R.string.status_already_listed_msg);
            return;
        }
        if (falsePositive && BlocklistStore.MATCHER.match(host) == null) {
            result.setText(R.string.report_not_blocked);
            return;
        }
        if (!ReportClient.isConfigured()) {
            result.setText(R.string.report_not_configured);
            return;
        }
        result.setText(R.string.working);
        final String kind = falsePositive ? "false_positive" : "betting";
        final String note = noteInput.getText().toString();
        new Thread(() -> {
            ReportClient.SubmitResult r = ReportClient.submit(getApplicationContext(), host, kind, note);
            runOnUiThread(() -> {
                if (isFinishing()) return;
                if (r.ok) {
                    result.setText(getString(R.string.report_sent, statusLabel(r.status)));
                    urlInput.setText("");
                    noteInput.setText("");
                    showMine();
                } else {
                    result.setText(errorLabel(r.error));
                }
            });
        }).start();
    }

    private void refreshStatuses() {
        new Thread(() -> {
            ReportClient.refreshStatuses(getApplicationContext());
            runOnUiThread(() -> {
                if (!isFinishing()) showMine();
            });
        }).start();
    }

    private void showMine() {
        myReports.removeAllViews();
        List<ReportClient.Report> list = ReportClient.mine(this);
        if (list.isEmpty()) {
            myReports.addView(Ui.text(this, getString(R.string.report_none), 14, false, R.color.subtext));
            return;
        }
        for (ReportClient.Report r : list) {
            LinearLayout row = Ui.card(this);
            row.addView(Ui.text(this, r.domain, 16, true, R.color.text));
            row.addView(Ui.text(this, statusLabel(r.status) + "  ·  " + formatTime(r.time), 13, false, R.color.subtext));
            myReports.addView(row, Ui.lp(this, 8));
        }
    }

    private String statusLabel(String status) {
        if (status == null) return "";
        switch (status) {
            case "pending_review": return getString(R.string.status_pending);
            case "under_review": return getString(R.string.status_under_review);
            case "approved": return getString(R.string.status_approved);
            case "rejected": return getString(R.string.status_rejected);
            case "already_listed": return getString(R.string.status_already_listed);
            default: return status;
        }
    }

    private String errorLabel(String code) {
        if (code == null) return getString(R.string.err_generic);
        switch (code) {
            case "invalid_url": return getString(R.string.report_invalid);
            case "network": return getString(R.string.err_network);
            case "rate_limited": return getString(R.string.err_rate_limited);
            case "duplicate": return getString(R.string.err_duplicate);
            case "protected": return getString(R.string.report_protected);
            case "not_configured": return getString(R.string.report_not_configured);
            default: return getString(R.string.err_generic);
        }
    }
}
