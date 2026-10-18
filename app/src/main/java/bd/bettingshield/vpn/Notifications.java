package bd.bettingshield.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import bd.bettingshield.R;
import bd.bettingshield.ui.MainActivity;

final class Notifications {

    static final String CHANNEL_STATUS = "protection_status";
    static final String CHANNEL_ALERT = "protection_alert";
    static final int ID_STATUS = 1;
    static final int ID_ALERT = 2;

    private Notifications() {}

    static void ensureChannels(Context c) {
        NotificationManager nm = c.getSystemService(NotificationManager.class);
        NotificationChannel status = new NotificationChannel(
                CHANNEL_STATUS, c.getString(R.string.notif_channel_status), NotificationManager.IMPORTANCE_LOW);
        NotificationChannel alert = new NotificationChannel(
                CHANNEL_ALERT, c.getString(R.string.notif_channel_alert), NotificationManager.IMPORTANCE_HIGH);
        nm.createNotificationChannel(status);
        nm.createNotificationChannel(alert);
    }

    private static PendingIntent openApp(Context c) {
        Intent i = new Intent(c, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP);
        return PendingIntent.getActivity(c, 0, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
    }

    static Notification statusNotification(Context c) {
        ensureChannels(c);
        return new Notification.Builder(c, CHANNEL_STATUS)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(c.getString(R.string.notif_active_title))
                .setContentText(c.getString(R.string.notif_active_text))
                .setContentIntent(openApp(c))
                .setOngoing(true)
                .build();
    }

    /** "Protection stopped" warning: shown when the VPN is revoked or cannot be restarted. */
    static void showStopped(Context c, String reason) {
        ensureChannels(c);
        Notification n = new Notification.Builder(c, CHANNEL_ALERT)
                .setSmallIcon(R.drawable.ic_shield)
                .setContentTitle(c.getString(R.string.notif_stopped_title))
                .setContentText(reason)
                .setStyle(new Notification.BigTextStyle().bigText(reason))
                .setContentIntent(openApp(c))
                .setAutoCancel(true)
                .build();
        c.getSystemService(NotificationManager.class).notify(ID_ALERT, n);
    }

    static void clearStopped(Context c) {
        c.getSystemService(NotificationManager.class).cancel(ID_ALERT);
    }
}
