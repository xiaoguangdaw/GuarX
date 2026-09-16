package com.auto.guardx

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

/**
 * GuardService —— 前台服务，让监控常驻后台不被杀。
 *
 * 提供一个静态入口 Singleton，供 MainActivity 直接拿引擎实例，
 * 这样 UI 就能实时订阅事件。
 */
class GuardService : Service() {

    companion object {
        const val CHANNEL_ID = "guardx_monitor"
        const val NOTI_ID = 1001

        /** 全局单例引擎，UI 直接读它拿状态 */
        @Volatile
        var engine: MonitorEngine? = null
            private set

        /** 最近的实时事件（给 UI 拉取） */
        val recentEvents = java.util.concurrent.ConcurrentLinkedQueue<GuardStore.LogEntry>()

        /** 启动服务 */
        fun start(ctx: Context) {
            val i = Intent(ctx, GuardService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                ctx.startForegroundService(i)
            } else {
                ctx.startService(i)
            }
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, GuardService::class.java))
        }
    }

    private var localEngine: MonitorEngine? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createChannel()
        startForeground(NOTI_ID, buildNotification("正在启动…"))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (localEngine == null || localEngine?.isRunning() != true) {
            RootShell.probeRoot()

            val e = MonitorEngine(
                ctx = applicationContext,
                onEvent = { entry ->
                    recentEvents.add(entry)
                    while (recentEvents.size > 200) recentEvents.poll()
                    // 通知栏更新（有可疑时提示）
                },
                onSuspicious = { sus ->
                    notifySuspicious(sus)
                },
                onStatus = { status ->
                    updateForeground(status)
                }
            )
            e.start()
            localEngine = e
            engine = e
            GuardStore.setRunning(this, true)
        }
        // 被系统杀掉后自动重启
        return START_STICKY
    }

    override fun onDestroy() {
        localEngine?.stop()
        localEngine = null
        engine = null
        GuardStore.setRunning(this, false)
        super.onDestroy()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                val ch = NotificationChannel(
                    CHANNEL_ID, "GuardX 监控",
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = "文件监控守护进程"
                    setShowBadge(false)
                }
                nm.createNotificationChannel(ch)
            }
        }
    }

    private fun buildNotification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("GuardX 守护")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setOngoing(true)
            .setContentIntent(pi)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun updateForeground(status: String) {
        try {
            val nm = getSystemService(NotificationManager::class.java)
            nm.notify(NOTI_ID, buildNotification(status))
        } catch (_: Throwable) {
        }
    }

    /** 发现可疑文件时单独弹一条高优先级通知 */
    private fun notifySuspicious(sus: GuardStore.SuspiciousEntry) {
        try {
            val nm = getSystemService(NotificationManager::class.java)
            val pi = PendingIntent.getActivity(
                this, 1,
                Intent(this, MainActivity::class.java).apply {
                    putExtra("open", "suspicious")
                },
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            )
            val n = NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("⚠ 发现可疑文件")
                .setContentText("${sus.path.substringAfterLast('/')} · ${sus.reason}")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setContentIntent(pi)
                .setAutoCancel(true)
                .setPriority(NotificationCompat.PRIORITY_HIGH)
                .build()
            nm.notify((System.currentTimeMillis() % 100000).toInt() + 2000, n)
        } catch (_: Throwable) {
        }
    }
}