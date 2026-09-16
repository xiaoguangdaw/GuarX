package com.auto.guardx

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/**
 * BootReceiver —— 开机自启。
 * 如果用户开了自动启动且之前处于运行状态，开机后自动拉起监控。
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        val action = intent?.action ?: return
        if (action != Intent.ACTION_BOOT_COMPLETED &&
            action != "android.intent.action.QUICKBOOT_POWERON"
        ) return

        val cfg = GuardStore.getConfig(context)
        val autoStart = cfg.optBoolean("autoStart", true)
        if (autoStart) {
            GuardService.start(context)
        }
    }
}