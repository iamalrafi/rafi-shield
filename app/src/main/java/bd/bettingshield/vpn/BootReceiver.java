package bd.bettingshield.vpn;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import bd.bettingshield.R;
import bd.bettingshield.data.Prefs;

/** Restarts protection after the phone reboots or the app is updated, if the user had it on. */
public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        String a = intent == null ? null : intent.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(a) && !Intent.ACTION_MY_PACKAGE_REPLACED.equals(a)) return;

        UpdateJobService.schedule(context);

        if (!Prefs.isProtectionWanted(context)) return;

        if (VpnService.prepare(context) == null) {
            try {
                ShieldVpnService.start(context);
            } catch (RuntimeException e) {
                // Some phones restrict background starts: tell the user instead of failing silently.
                Notifications.showStopped(context, context.getString(R.string.notif_stopped_cannot_start));
            }
        } else {
            // VPN permission is gone (for example another VPN app was approved): ask the user.
            Notifications.showStopped(context, context.getString(R.string.notif_stopped_permission));
        }
    }
}
