package bd.bettingshield.ui;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.widget.LinearLayout;
import bd.bettingshield.R;
import bd.bettingshield.data.BlocklistStore;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Shows installed apps that match the known betting-app list.
 * Android does not let a normal app stop another app from launching, so this screen can only
 * detect and offer to uninstall (the user confirms in a system dialog).
 */
public class AppsActivity extends BaseActivity {

    private LinearLayout listBox;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        BlocklistStore.load(this);
        LinearLayout p = page(getString(R.string.apps_title), true);
        p.addView(Ui.text(this, getString(R.string.apps_intro), 15, false, R.color.subtext), Ui.lp(this, 6));
        listBox = new LinearLayout(this);
        listBox.setOrientation(LinearLayout.VERTICAL);
        p.addView(listBox, Ui.lp(this, 12));
        p.addView(Ui.text(this, getString(R.string.apps_limit), 13, false, R.color.subtext), Ui.lp(this, 16));
    }

    @Override
    protected void onResume() {
        super.onResume();
        scan();
    }

    private void scan() {
        listBox.removeAllViews();
        PackageManager pm = getPackageManager();
        List<String> found = new ArrayList<>();
        for (String pkg : BlocklistStore.bettingAppPackages()) {
            try {
                pm.getPackageInfo(pkg, 0);
                found.add(pkg);
            } catch (PackageManager.NameNotFoundException ignored) {
                // not installed
            }
        }
        Collections.sort(found);
        if (found.isEmpty()) {
            LinearLayout ok = Ui.coloredCard(this, R.color.ok_bg);
            ok.addView(Ui.text(this, getString(R.string.apps_none, BlocklistStore.bettingAppPackages().size()),
                    15, false, R.color.text));
            listBox.addView(ok);
            return;
        }
        listBox.addView(Ui.text(this, getString(R.string.apps_found, found.size()), 16, true, R.color.bad));
        for (String pkg : found) {
            CharSequence label = pkg;
            try {
                label = pm.getApplicationLabel(pm.getApplicationInfo(pkg, 0));
            } catch (PackageManager.NameNotFoundException ignored) {
                // keep package name
            }
            LinearLayout row = Ui.card(this);
            row.addView(Ui.text(this, label, 17, true, R.color.text));
            row.addView(Ui.text(this, pkg, 12, false, R.color.subtext));
            final String target = pkg;
            row.addView(Ui.button(this, getString(R.string.uninstall), true, v -> {
                Intent i = new Intent(Intent.ACTION_DELETE, Uri.parse("package:" + target));
                startActivity(i);
            }), Ui.lp(this, 10));
            listBox.addView(row, Ui.lp(this, 10));
        }
    }
}
