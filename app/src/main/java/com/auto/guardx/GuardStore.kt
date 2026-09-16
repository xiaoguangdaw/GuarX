package com.auto.guardx

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * GuardStore —— 数据持久化。
 *
 * 用纯 JSON 文件存储（避免引入 Room 造成依赖冲突），所有数据放私有目录：
 *   files/baseline.json  已知文件基线（路径 → 时间戳）
 *   files/whitelist.json 白名单（用户标记为正常的路径）
 *   files/logs.json      事件日志（环形，最多 N 条）
 *   files/suspicious.json 待处理的可疑文件
 */
object GuardStore {

    private const val F_BASELINE = "baseline.json"
    private const val F_WHITELIST = "whitelist.json"
    private const val F_LOGS = "logs.json"
    private const val F_SUSPICIOUS = "suspicious.json"
    private const val F_CONFIG = "config.json"

    const val MAX_LOGS = 500

    // ---------- 数据模型 ----------

    data class LogEntry(
        val time: Long,
        val action: String,     // NEW / DELETE / MODIFY
        val path: String,
        val source: String,     // 溯源结果
        val size: Long,
        val verified: Boolean = false  // 是否已确认真实存在（复查过）
    )

    data class SuspiciousEntry(
        val time: Long,
        val path: String,
        val source: String,
        val size: Long,
        val reason: String,
        var handled: Boolean = false  // 用户是否已处理
    )

    data class MonitorDir(
        val path: String,
        var enabled: Boolean = true
    )

    // ---------- 工具 ----------

    private fun file(ctx: Context, name: String): File {
        val dir = File(ctx.filesDir, "guardx")
        if (!dir.exists()) dir.mkdirs()
        return File(dir, name)
    }

    private fun readJson(ctx: Context, name: String): JSONObject? {
        return try {
            val f = file(ctx, name)
            if (!f.exists()) null else JSONObject(f.readText())
        } catch (_: Throwable) {
            null
        }
    }

    private fun writeJson(ctx: Context, name: String, obj: JSONObject) {
        try {
            file(ctx, name).writeText(obj.toString())
        } catch (_: Throwable) {
        }
    }

    // ---------- 配置 ----------

    /** 默认监控两个目标目录 */
    private val defaultDirs = listOf(
        "/sdcard/Download",
        "/sdcard/Android/data"
    )

    fun getConfig(ctx: Context): JSONObject {
        return readJson(ctx, F_CONFIG) ?: JSONObject().apply {
            put("running", false)
            put("autoStart", true)
            val arr = JSONArray()
            defaultDirs.forEach { arr.put(it) }
            put("dirs", arr)
            put("baselineReady", false)
        }
    }

    fun saveConfig(ctx: Context, obj: JSONObject) = writeJson(ctx, F_CONFIG, obj)

    fun getDirs(ctx: Context): List<String> {
        val cfg = getConfig(ctx)
        val arr = cfg.optJSONArray("dirs") ?: JSONArray()
        val list = ArrayList<String>()
        for (i in 0 until arr.length()) list.add(arr.getString(i))
        return list
    }

    fun setDirs(ctx: Context, dirs: List<String>) {
        val cfg = getConfig(ctx)
        val arr = JSONArray()
        dirs.forEach { arr.put(it) }
        cfg.put("dirs", arr)
        saveConfig(ctx, cfg)
    }

    fun isRunning(ctx: Context): Boolean = getConfig(ctx).optBoolean("running", false)

    fun setRunning(ctx: Context, r: Boolean) {
        val cfg = getConfig(ctx)
        cfg.put("running", r)
        saveConfig(ctx, cfg)
    }

    fun isBaselineReady(ctx: Context): Boolean = getConfig(ctx).optBoolean("baselineReady", false)

    fun setBaselineReady(ctx: Context, r: Boolean) {
        val cfg = getConfig(ctx)
        cfg.put("baselineReady", r)
        saveConfig(ctx, cfg)
    }

    // ---------- 基线 ----------

    /** 基线：路径集合（只存路径，不存内容，不占空间） */
    fun loadBaseline(ctx: Context): MutableSet<String> {
        val set = HashSet<String>()
        val obj = readJson(ctx, F_BASELINE) ?: return set
        val arr = obj.optJSONArray("paths") ?: return set
        for (i in 0 until arr.length()) set.add(arr.getString(i))
        return set
    }

    fun saveBaseline(ctx: Context, set: Set<String>) {
        val arr = JSONArray()
        set.forEach { arr.put(it) }
        writeJson(ctx, F_BASELINE, JSONObject().put("paths", arr))
    }

    /** 增量添加一条基线（用户确认正常时调用） */
    fun addToBaseline(ctx: Context, path: String) {
        val set = loadBaseline(ctx)
        set.add(path)
        saveBaseline(ctx, set)
    }

    // ---------- 白名单 ----------

    fun loadWhitelist(ctx: Context): MutableSet<String> {
        val set = HashSet<String>()
        val obj = readJson(ctx, F_WHITELIST) ?: return set
        val arr = obj.optJSONArray("paths") ?: return set
        for (i in 0 until arr.length()) set.add(arr.getString(i))
        return set
    }

    fun addWhitelist(ctx: Context, path: String) {
        val set = loadWhitelist(ctx)
        set.add(path)
        val arr = JSONArray()
        set.forEach { arr.put(it) }
        writeJson(ctx, F_WHITELIST, JSONObject().put("paths", arr))
    }

    fun removeWhitelist(ctx: Context, path: String) {
        val set = loadWhitelist(ctx)
        set.remove(path)
        val arr = JSONArray()
        set.forEach { arr.put(it) }
        writeJson(ctx, F_WHITELIST, JSONObject().put("paths", arr))
    }

    // ---------- 日志 ----------

    fun loadLogs(ctx: Context): MutableList<LogEntry> {
        val list = ArrayList<LogEntry>()
        val obj = readJson(ctx, F_LOGS) ?: return list
        val arr = obj.optJSONArray("logs") ?: return list
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            list.add(
                LogEntry(
                    time = o.optLong("t"),
                    action = o.optString("a"),
                    path = o.optString("p"),
                    source = o.optString("s"),
                    size = o.optLong("z"),
                    verified = o.optBoolean("v")
                )
            )
        }
        return list
    }

    fun addLog(ctx: Context, entry: LogEntry) {
        val list = loadLogs(ctx)
        list.add(0, entry) // 新的在前
        while (list.size > MAX_LOGS) list.removeAt(list.size - 1)
        val arr = JSONArray()
        list.forEach { e ->
            arr.put(JSONObject().apply {
                put("t", e.time)
                put("a", e.action)
                put("p", e.path)
                put("s", e.source)
                put("z", e.size)
                put("v", e.verified)
            })
        }
        writeJson(ctx, F_LOGS, JSONObject().put("logs", arr))
    }

    fun clearLogs(ctx: Context) {
        writeJson(ctx, F_LOGS, JSONObject().put("logs", JSONArray()))
    }

    // ---------- 可疑文件 ----------

    fun loadSuspicious(ctx: Context): MutableList<SuspiciousEntry> {
        val list = ArrayList<SuspiciousEntry>()
        val obj = readJson(ctx, F_SUSPICIOUS) ?: return list
        val arr = obj.optJSONArray("items") ?: return list
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            list.add(
                SuspiciousEntry(
                    time = o.optLong("t"),
                    path = o.optString("p"),
                    source = o.optString("s"),
                    size = o.optLong("z"),
                    reason = o.optString("r"),
                    handled = o.optBoolean("h")
                )
            )
        }
        return list
    }

    private fun saveSuspicious(ctx: Context, list: List<SuspiciousEntry>) {
        val arr = JSONArray()
        list.forEach { e ->
            arr.put(JSONObject().apply {
                put("t", e.time)
                put("p", e.path)
                put("s", e.source)
                put("z", e.size)
                put("r", e.reason)
                put("h", e.handled)
            })
        }
        writeJson(ctx, F_SUSPICIOUS, JSONObject().put("items", arr))
    }

    fun addSuspicious(ctx: Context, entry: SuspiciousEntry) {
        val list = loadSuspicious(ctx)
        // 去重：同路径只留最新
        list.removeAll { it.path == entry.path }
        list.add(0, entry)
        saveSuspicious(ctx, list)
    }

    /** 标记某条已处理 */
    fun markSuspiciousHandled(ctx: Context, path: String) {
        val list = loadSuspicious(ctx)
        list.forEach { if (it.path == path) it.handled = true }
        saveSuspicious(ctx, list)
    }

    /** 从可疑列表里移除（比如删除后） */
    fun removeSuspicious(ctx: Context, path: String) {
        val list = loadSuspicious(ctx)
        list.removeAll { it.path == path }
        saveSuspicious(ctx, list)
    }

    fun clearSuspicious(ctx: Context) {
        saveSuspicious(ctx, emptyList())
    }
}