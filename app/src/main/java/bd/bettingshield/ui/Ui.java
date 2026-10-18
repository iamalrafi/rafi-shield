package bd.bettingshield.ui;

import android.content.Context;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import bd.bettingshield.R;

/** Tiny helpers for building screens in code (keeps the project free of extra libraries). */
final class Ui {

    private Ui() {}

    static int dp(Context c, int v) {
        return Math.round(v * c.getResources().getDisplayMetrics().density);
    }

    static TextView text(Context c, CharSequence s, int sp, boolean bold, int colorRes) {
        TextView t = new TextView(c);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(c.getColor(colorRes));
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        t.setLineSpacing(0f, 1.15f);
        return t;
    }

    static LinearLayout.LayoutParams lp(Context c, int topDp) {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        p.topMargin = dp(c, topDp);
        return p;
    }

    static LinearLayout card(Context c) {
        LinearLayout l = new LinearLayout(c);
        l.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(c, 16);
        l.setPadding(pad, pad, pad, pad);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(c.getColor(R.color.card));
        bg.setCornerRadius(dp(c, 14));
        bg.setStroke(dp(c, 1), c.getColor(R.color.divider));
        l.setBackground(bg);
        return l;
    }

    static LinearLayout coloredCard(Context c, int fillRes) {
        LinearLayout l = card(c);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(c.getColor(fillRes));
        bg.setCornerRadius(dp(c, 14));
        l.setBackground(bg);
        return l;
    }

    static Button button(Context c, CharSequence label, boolean primary, View.OnClickListener l) {
        Button b = new Button(c);
        b.setText(label);
        b.setAllCaps(false);
        b.setTextSize(16);
        b.setGravity(Gravity.CENTER);
        int hp = dp(c, 16);
        b.setPadding(hp, dp(c, 12), hp, dp(c, 12));
        GradientDrawable bg = new GradientDrawable();
        bg.setCornerRadius(dp(c, 12));
        if (primary) {
            bg.setColor(c.getColor(R.color.primary));
            b.setTextColor(c.getColor(R.color.on_primary));
        } else {
            bg.setColor(c.getColor(R.color.card));
            bg.setStroke(dp(c, 1), c.getColor(R.color.primary));
            b.setTextColor(c.getColor(R.color.primary));
        }
        b.setBackground(bg);
        b.setOnClickListener(l);
        return b;
    }
}
