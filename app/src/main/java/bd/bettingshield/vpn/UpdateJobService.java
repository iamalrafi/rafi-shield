package bd.bettingshield.vpn;

import android.app.job.JobInfo;
import android.app.job.JobParameters;
import android.app.job.JobScheduler;
import android.app.job.JobService;
import android.content.ComponentName;
import android.content.Context;
import bd.bettingshield.data.BlocklistStore;

/** Checks for a new blocklist about every 12 hours when the internet is available. */
public class UpdateJobService extends JobService {

    private static final int JOB_ID = 4001;

    public static void schedule(Context c) {
        JobScheduler js = c.getSystemService(JobScheduler.class);
        if (js == null) return;
        for (JobInfo j : js.getAllPendingJobs()) {
            if (j.getId() == JOB_ID) return; // already scheduled
        }
        JobInfo info = new JobInfo.Builder(JOB_ID, new ComponentName(c, UpdateJobService.class))
                .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
                .setPeriodic(12L * 60 * 60 * 1000)
                .setPersisted(true)
                .build();
        js.schedule(info);
    }

    @Override
    public boolean onStartJob(final JobParameters params) {
        new Thread(() -> {
            BlocklistStore.update(getApplicationContext(), false);
            jobFinished(params, false);
        }, "list-update-job").start();
        return true; // work continues on the background thread
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        return true; // retry later
    }
}
