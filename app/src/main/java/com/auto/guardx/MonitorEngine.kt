package com.auto.guardx

import android.content.Context
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * MonitorEngine —— 监控引擎（真本事所在）。
 *
 * 为什么不用 FileObserver？
 *   FileObserver 在 /sdcard/Android/data 这类受限目录上收不到事件，
 *   而且它只能监听单层目录，深层树要建成千上万个观察者，开销巨大。
 *
 * 所以采用：root 扫描对比。周期性地用 root 列出监控目录下的全部文件，
 * 与上一轮的快照做 diff：
 *   本轮有、上轮没有  → 新增（可能是被塞进来的标记文件）
 *   上轮有、本轮没有  → 删除
 *   两边都有但大小变了 → 修改
 *
 * 为了不卡手机，做了限流：
 *   - 扫描在后台线程，且线程优先级降到最低
 *   - 只对"新增"做昂贵的进程溯源（删除/修改不溯源，省时间）
 *   - 每轮扫描之间的间隔可调（默认 8 秒）
 */
class MonitorEngine(
    private val ctx: Context,
    private val onEvent: (GuardStore.LogEntry) -> Unit,
    private val onSuspicious: (GuardStore.SuspiciousEntry) -> Unit,
    private val onStatus: (String) -> Unit
) {

    private val running = AtomicBoolean(false)
    private var worker: Thread? = null

    /** 上一轮的文件快照：路径 -> size */
    private var snapshot: MutableMap<String, Long> = HashMap()

    /** 扫描间隔（毫秒），太快会耗电，太慢会漏 */
    @Volatile
    var intervalMs: Long = 8000

    /** 首次是否已建立快照 */
    private var primed = false

    // ---------- 给 UI 读的实时信息 ----------
    private val filesNow = AtomicInteger(0)
    private val lastScanAt = AtomicLong(0L)

    fun isRunning(): Boolean = running.get()

    /** 最近一轮扫描看到的文件总数（UI 显示用） */
    fun fileCount(): Int = filesNow.get()

    /** 最近一次扫描的时间戳（UI 显示用） */
    fun lastScanTime(): Long = lastScanAt.get()

    /**
     * 启动监控。
     * 第一次启动时，先把当前文件全部当作"已知"（等同建立基线），不报警。
     * 之后的增量才报警。
     */
    fun start() {
        if (running.get()) return
        running.set(true)
        primed = false
        snapshot = HashMap()

        worker = Thread {
            try {
                onStatus("正在首次扫描，建立基线…")
                // 第一轮：只建立快照，不报告
                val first = scanAll()
                snapshot = first
                filesNow.set(first.size)
                lastScanAt.set(System.currentTimeMillis())
                primed = true
                GuardStore.setBaselineReady(ctx, true)
                onStatus("监控中 · 基线 ${first.size} 个文件")

                while (running.get()) {
                    try {
                        Thread.sleep(intervalMs)
                    } catch (_: InterruptedException) {
                        break
                    }
                    if (!running.get()) break

                    try {
                        val current = scanAll()
                        if (primed) diffAndReport(current)
                        snapshot = current
                        filesNow.set(current.size)
                        lastScanAt.set(System.currentTimeMillis())
                        onStatus("监控中 · ${current.size} 个文件")
                    } catch (e: Throwable) {
                        onStatus("扫描出错: ${e.message}")
                    }
                }
            } catch (_: Throwable) {
            } finally {
                onStatus("已停止")
            }
        }.also {
            it.isDaemon = true
            it.priority = Thread.MIN_PRIORITY
            it.start()
        }
    }

    fun stop() {
        running.set(false)
        worker?.interrupt()
        worker = null
    }

    /**
     * 扫描所有监控目录，返回 路径->大小 的映射。
     * 用 root 的 find 一条命令搞定，比 JVM 递归快得多，
     * 而且能穿透 /sdcard/Android/data 的限制。
     */
    private fun scanAll(): MutableMap<String, Long> {
        val result = HashMap<String, Long>()
        val dirs = GuardStore.getDirs(ctx).filter { File(it).exists() || true }
        if (dirs.isEmpty()) return result

        // 拼成一条 find 命令，输出格式： 路径<TAB>大小
        val dirArgs = dirs.joinToString(" ") { "'${it.replace("'", "'\\''")}'" }
        val cmd = "find $dirArgs -type f -printf '%p\\t%s\\n' 2>/dev/null"

        val out = RootShell.exec(cmd, 25000)
        for (line in out.lines()) {
            if (line.isBlank()) continue
            val tab = line.lastIndexOf('\t')
            if (tab <= 0) continue
            val path = line.substring(0, tab)
            val size = line.substring(tab + 1).trim().toLongOrNull() ?: 0L
            result[path] = size
        }
        return result
    }

    /**
     * 对比两轮快照，产生事件。
     * 注意：本轮快照已在主循环里赋值，这里对比的是"上一轮"。
     */
    private fun diffAndReport(current: MutableMap<String, Long>) {
        val whitelist = GuardStore.loadWhitelist(ctx)
        val now = System.currentTimeMillis()

        // 新增 + 修改
        for ((path, size) in current) {
            val old = snapshot[path]
            if (old == null) {
                // 新增文件 → 这是重点，需要溯源
                val source = RootShell.attribute(path)
                val entry = GuardStore.LogEntry(
                    time = now, action = "NEW", path = path,
                    source = source, size = size
                )
                onEvent(entry)
                GuardStore.addLog(ctx, entry)

                if (path !in whitelist) {
                    val reason = judge(path, size, source)
                    val sus = GuardStore.SuspiciousEntry(
                        time = now, path = path, source = source,
                        size = size, reason = reason
                    )
                    GuardStore.addSuspicious(ctx, sus)
                    onSuspicious(sus)
                }
            } else if (old != size) {
                // 修改
                val entry = GuardStore.LogEntry(
                    time = now, action = "MODIFY", path = path,
                    source = "未知来源", size = size
                )
                onEvent(entry)
                GuardStore.addLog(ctx, entry)
            }
        }

        // 删除
        for (path in snapshot.keys) {
            if (path !in current) {
                val entry = GuardStore.LogEntry(
                    time = now, action = "DELETE", path = path,
                    source = "未知来源", size = 0
                )
                onEvent(entry)
                GuardStore.addLog(ctx, entry)
            }
        }
    }

    /**
     * 可疑度判断：不是所有新文件都值得报警。
     * 规则（越靠前越可疑）：
     *  1. 文件名含可疑关键词
     *  2. 无扩展名的长随机文件名
     *  3. Android/data 下的超小文件（典型"标记文件"）
     *  4. Android/data 下新增且无法溯源
     *  都不命中 → "普通新增"，仅记录不重点提醒
     */
    private fun judge(path: String, size: Long, source: String): String {
        val name = path.substringAfterLast('/').lowercase()
        val reasons = ArrayList<String>()

        val keywords = listOf(
            "mark", "ban", "flag", "blacklist", "detect", "trace",
            "uuid", "device_id", "machine"
        )
        for (k in keywords) {
            if (name.contains(k)) {
                reasons.add("文件名含可疑关键词「$k」")
                break
            }
        }

        // 随机长串文件名（无扩展名且长度 >= 16）
        val noExt = !name.contains('.')
        if (noExt && name.length >= 16) reasons.add("无扩展名的长随机文件名")

        // 小体积 + Android/data
        if (size in 1..4096 && path.contains("/Android/data/")) {
            reasons.add("位于 Android/data 下的超小文件（典型标记文件特征）")
        }

        if (source.contains("未知来源") && path.contains("/Android/data/")) {
            reasons.add("Android/data 下新增且无法溯源来源")
        }

        return if (reasons.isEmpty()) "普通新增" else reasons.joinToString("；")
    }
}