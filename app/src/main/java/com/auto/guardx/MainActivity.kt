package com.auto.guardx

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.WebView
import android.webkit.WebViewClient
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * MainActivity —— UI 载体。
 *
 * 界面用 WebView 承载 assets/index.html（沿用原来那份 HTML 的风格），
 * 但页面里**没有假功能**：所有数据都通过 JsBridge 从真实引擎读取。
 *
 * 暴露给 JS 的接口（window.GuardX.*）：
 *   ready()                是否已完成初始化
 *   getStatus()            当前状态（root / 运行 / 基线 / 文件数 / 可疑数）
 *   startGuard() / stopGuard()
 *   getSuspicious()        可疑文件列表（真实扫描结果）
 *   deleteSuspicious(path) 用 root 真删
 *   whitelist(path)        标记为正常（进白名单 + 移出可疑）
 *   getLogs(limit)         事件日志
 *   clearLogs()            清空日志
 *   getDirs() / addDir(p) / removeDir(p)
 *   getWhitelist() / unwhitelist(p)
 *   requestStorage()       申请存储权限
 *   openAppSettings()      跳系统权限页（给 root 授权）
 *   openPath(path)         用系统应用打开文件（可疑文件跳转）
 *   getPerms()             {storage, notify, root} 权限状态（v2 权限中心）
 *   openPerm(kind)         按类型申请/跳转权限（v2 权限中心）
 */
class MainActivity : AppCompatActivity() {

    private lateinit var web: WebView
    private val main = Handler(Looper.getMainLooper())
    private val fmt = SimpleDateFormat("MM-dd HH:mm:ss", Locale.CHINA)

    /** 给 JS 的实时状态缓存 */
    @Volatile
    private var lastStatus: String = ""

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        web = WebView(this)
        setContentView(web)

        web.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = true
            loadWithOverviewMode = true
            useWideViewPort = true
            @Suppress("DEPRECATION")
            allowUniversalAccessFromFileURLs = true
        }
        web.webViewClient = WebViewClient()
        web.addJavascriptInterface(JsBridge(), "GuardX")

        web.loadUrl("file:///android_asset/index.html")

        // 启动后探测 root（后台线程，避免卡 UI）
        Thread {
            RootShell.probeRoot()
            main.post { pushStatus() }
        }.also { it.isDaemon = true; it.start() }

        // 每 2 秒把最新状态推给页面（页面自己决定要不要重绘）
        main.post(object : Runnable {
            override fun run() {
                pushStatus()
                main.postDelayed(this, 2000)
            }
        })

        requestStorageIfNeeded()
    }

    override fun onDestroy() {
        super.onDestroy()
    }

    // ---------------- 状态推送 ----------------

    private fun pushStatus() {
        val s = buildStatus().toString()
        if (s == lastStatus) return
        lastStatus = s
        // 直接调用页面里的回调函数（存在才调）
        web.evaluateJavascript(
            "window.__guardxStatus && window.__guardxStatus($s);", null
        )
    }

    private fun buildStatus(): JSONObject {
        val ctx = applicationContext
        val engine = GuardService.engine
        val suspicious = GuardStore.loadSuspicious(ctx).count { !it.handled }
        return JSONObject().apply {
            put("root", RootShell.hasRoot)
            put("running", engine?.isRunning() == true)
            put("baselineReady", GuardStore.isBaselineReady(ctx))
            put("suspiciousCount", suspicious)
            put("fileCount", engine?.fileCount() ?: 0)
            put("lastScan", engine?.lastScanTime() ?: 0)
            put("autoStart", GuardStore.getConfig(ctx).optBoolean("autoStart", true))
            put("dirs", JSONArray(GuardStore.getDirs(ctx)))
        }
    }

    // ---------------- 权限 ----------------

    private fun requestStorageIfNeeded() {
        if (Build.VERSION.SDK_INT >= 30) {
            // Android 11+ 用「所有文件访问权限」
            if (!Environment.isExternalStorageManager()) {
                try {
                    startActivity(
                        Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                            .setData(Uri.parse("package:$packageName"))
                    )
                } catch (_: Throwable) {
                    try {
                        startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                    } catch (_: Throwable) {
                    }
                }
            }
        } else {
            val need = ContextCompat.checkSelfPermission(
                this, Manifest.permission.READ_EXTERNAL_STORAGE
            ) != PackageManager.PERMISSION_GRANTED
            if (need) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(
                        Manifest.permission.READ_EXTERNAL_STORAGE,
                        Manifest.permission.WRITE_EXTERNAL_STORAGE
                    ),
                    1001
                )
            }
        }
        // Android 13+ 通知权限
        if (Build.VERSION.SDK_INT >= 33) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1002
                )
            }
        }
    }

    /** 存储权限是否已授予（Android 11+ 看所有文件访问，否则看运行时权限） */
    private fun hasStoragePerm(): Boolean {
        return if (Build.VERSION.SDK_INT >= 30) {
            Environment.isExternalStorageManager()
        } else {
            ContextCompat.checkSelfPermission(
                this, Manifest.permission.READ_EXTERNAL_STORAGE
            ) == PackageManager.PERMISSION_GRANTED
        }
    }

    /** 通知权限是否已授予（Android 13 以下视为默认允许） */
    private fun hasNotifyPerm(): Boolean {
        if (Build.VERSION.SDK_INT < 33) return true
        return ContextCompat.checkSelfPermission(
            this, Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
    }

    /** 只申请/跳转存储权限（供权限中心 storage 项调用） */
    private fun requestStorageOnly() {
        if (Build.VERSION.SDK_INT >= 30) {
            if (!Environment.isExternalStorageManager()) {
                try {
                    startActivity(
                        Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                            .setData(Uri.parse("package:$packageName"))
                    )
                } catch (_: Throwable) {
                    try {
                        startActivity(Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION))
                    } catch (_: Throwable) {
                    }
                }
            }
        } else {
            if (!hasStoragePerm()) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(
                        Manifest.permission.READ_EXTERNAL_STORAGE,
                        Manifest.permission.WRITE_EXTERNAL_STORAGE
                    ),
                    1001
                )
            }
        }
    }

    /** 打开本应用详情页（统一入口，避免重复代码） */
    private fun openAppSettingsInternal() {
        try {
            startActivity(
                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                    .setData(Uri.parse("package:$packageName"))
            )
        } catch (_: Throwable) {
        }
    }

    // ---------------- JS 桥（真数据） ----------------

    inner class JsBridge {

        @JavascriptInterface
        fun getStatus(): String = buildStatus().toString()

        @JavascriptInterface
        fun startGuard(): String {
            if (!RootShell.hasRoot) RootShell.probeRoot()
            GuardService.start(applicationContext)
            GuardStore.setRunning(applicationContext, true)
            return buildStatus().toString()
        }

        @JavascriptInterface
        fun stopGuard(): String {
            GuardService.stop(applicationContext)
            GuardStore.setRunning(applicationContext, false)
            return buildStatus().toString()
        }

        @JavascriptInterface
        fun getSuspicious(): String {
            val list = GuardStore.loadSuspicious(applicationContext)
            val arr = JSONArray()
            list.forEach { e ->
                arr.put(JSONObject().apply {
                    put("time", fmt.format(Date(e.time)))
                    put("timeText", fmt.format(Date(e.time)))
                    put("path", e.path)
                    put("name", e.path.substringAfterLast('/'))
                    put("source", e.source)
                    put("origin", e.source)
                    put("size", humanSize(e.size))
                    put("sizeText", humanSize(e.size))
                    put("reason", e.reason)
                    put("handled", e.handled)
                })
            }
            return arr.toString()
        }

        /** 真删（root，能删任何路径） */
        @JavascriptInterface
        fun deleteSuspicious(path: String): Boolean {
            val ok = RootShell.delete(path)
            if (ok) {
                GuardStore.removeSuspicious(applicationContext, path)
            }
            return ok
        }

        /** 标记正常：进白名单，以后不再报；同时移出可疑列表 */
        @JavascriptInterface
        fun whitelist(path: String): Boolean {
            GuardStore.addWhitelist(applicationContext, path)
            GuardStore.addToBaseline(applicationContext, path)
            GuardStore.removeSuspicious(applicationContext, path)
            return true
        }

        @JavascriptInterface
        fun getLogs(limit: Int): String {
            val list = GuardStore.loadLogs(applicationContext)
            val arr = JSONArray()
            list.take(if (limit <= 0) 200 else limit).forEach { e ->
                arr.put(JSONObject().apply {
                    put("time", fmt.format(Date(e.time)))
                    put("timeText", fmt.format(Date(e.time)))
                    put("action", e.action)
                    put("act", e.action)
                    put("path", e.path)
                    put("name", e.path.substringAfterLast('/'))
                    put("source", e.source)
                    put("origin", e.source)
                    put("sizeText", humanSize(e.size))
                })
            }
            return arr.toString()
        }

        @JavascriptInterface
        fun clearLogs(): Boolean {
            GuardStore.clearLogs(applicationContext)
            return true
        }

        @JavascriptInterface
        fun getDirs(): String = JSONArray(GuardStore.getDirs(applicationContext)).toString()

        @JavascriptInterface
        fun addDir(path: String): Boolean {
            val p = path.trim().trimEnd('/')
            if (p.isEmpty() || !p.startsWith("/")) return false
            val dirs = GuardStore.getDirs(applicationContext).toMutableList()
            if (p !in dirs) {
                dirs.add(p)
                GuardStore.setDirs(applicationContext, dirs)
                GuardStore.setBaselineReady(applicationContext, false)
            }
            return true
        }

        @JavascriptInterface
        fun removeDir(path: String): Boolean {
            val dirs = GuardStore.getDirs(applicationContext).toMutableList()
            dirs.remove(path.trim().trimEnd('/'))
            GuardStore.setDirs(applicationContext, dirs)
            GuardStore.setBaselineReady(applicationContext, false)
            return true
        }

        @JavascriptInterface
        fun getWhitelist(): String =
            JSONArray(GuardStore.loadWhitelist(applicationContext).toList()).toString()

        @JavascriptInterface
        fun unwhitelist(path: String): Boolean {
            GuardStore.removeWhitelist(applicationContext, path)
            return true
        }

        @JavascriptInterface
        fun setAutoStart(on: Boolean): Boolean {
            val cfg = GuardStore.getConfig(applicationContext)
            cfg.put("autoStart", on)
            GuardStore.saveConfig(applicationContext, cfg)
            return true
        }

        /** 手动重新建立基线（当前文件全部视为已知，清空可疑） */
        @JavascriptInterface
        fun rebuildBaseline(): Boolean {
            GuardStore.clearSuspicious(applicationContext)
            GuardStore.setBaselineReady(applicationContext, false)
            val e = GuardService.engine
            if (e != null) {
                e.stop()
                e.start()
            } else {
                GuardService.start(applicationContext)
            }
            return true
        }

        @JavascriptInterface
        fun requestStorage(): Boolean {
            main.post { requestStorageIfNeeded() }
            return true
        }

        @JavascriptInterface
        fun openAppSettings(): Boolean {
            main.post { openAppSettingsInternal() }
            return true
        }

        @JavascriptInterface
        fun openPath(path: String): Boolean {
            main.post {
                try {
                    val i = Intent(Intent.ACTION_VIEW)
                    i.setDataAndType(Uri.parse("file://$path"), "*/*")
                    i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    startActivity(i)
                } catch (_: Throwable) {
                }
            }
            return true
        }

        /** 权限状态：{storage, notify, root} 交给 v2 权限中心页渲染 */
        @JavascriptInterface
        fun getPerms(): String {
            return JSONObject().apply {
                put("storage", hasStoragePerm())
                put("notify", hasNotifyPerm())
                put("root", RootShell.hasRoot)
            }.toString()
        }

        /**
         * 按类型跳转/申请权限：
         *   storage -> 所有文件访问权限（Android 11+）或运行时读写权限
         *   notify  -> Android 13+ 通知运行时权限
         *   root    -> 直接打开本应用详情页（由用户去 Magisk/LSPosed 授权）
         */
        @JavascriptInterface
        fun openPerm(kind: String): Boolean {
            main.post {
                when (kind) {
                    "storage" -> requestStorageOnly()
                    "notify" -> {
                        if (Build.VERSION.SDK_INT >= 33) {
                            ActivityCompat.requestPermissions(
                                this@MainActivity,
                                arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                                1002
                            )
                        } else {
                            openAppSettingsInternal()
                        }
                    }
                    else -> openAppSettingsInternal()
                }
            }
            return true
        }

        @JavascriptInterface
        fun getRecentEvents(): String {
            val arr = JSONArray()
            GuardService.recentEvents.toList().takeLast(100).forEach { e ->
                arr.put(JSONObject().apply {
                    put("time", fmt.format(Date(e.time)))
                    put("timeText", fmt.format(Date(e.time)))
                    put("action", e.action)
                    put("act", e.action)
                    put("name", e.path.substringAfterLast('/'))
                    put("path", e.path)
                    put("source", e.source)
                    put("origin", e.source)
                })
            }
            return arr.toString()
        }
    }

    companion object {
        fun humanSize(b: Long): String = when {
            b <= 0 -> "0 B"
            b < 1024 -> "$b B"
            b < 1024 * 1024 -> String.format(Locale.US, "%.1f KB", b / 1024.0)
            else -> String.format(Locale.US, "%.1f MB", b / 1024.0 / 1024.0)
        }
    }
}