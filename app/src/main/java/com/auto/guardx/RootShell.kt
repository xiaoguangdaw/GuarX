package com.auto.guardx

import java.io.BufferedReader
import java.io.DataOutputStream
import java.io.InputStreamReader

/**
 * RootShell —— 负责执行 root 命令，以及通过 /proc 反查进程。
 *
 * 这是 GuardX 的"手"：删除文件、读目录、查进程归属，全靠它。
 */
object RootShell {

    /** 是否具备 root 权限（启动时探测一次即可） */
    @Volatile
    var hasRoot: Boolean = false
        private set

    /**
     * 探测 root：执行 id，看是否返回 uid=0(root)
     */
    fun probeRoot(): Boolean {
        return try {
            val out = exec("id")
            hasRoot = out.contains("uid=0")
            hasRoot
        } catch (e: Throwable) {
            hasRoot = false
            false
        }
    }

    /**
     * 执行 root 命令，返回 stdout + stderr 合并输出。
     * 使用 su -c 方式，兼容 Magisk / KernelSU / APatch。
     */
    fun exec(cmd: String, timeoutMs: Long = 15000): String {
        val sb = StringBuilder()
        var process: Process? = null
        try {
            process = ProcessBuilder("su", "-c", cmd)
                .redirectErrorStream(true)
                .start()

            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val done = java.util.concurrent.CountDownLatch(1)

            val t = Thread {
                try {
                    var line: String?
                    while (reader.readLine().also { line = it } != null) {
                        sb.append(line).append('\n')
                    }
                } catch (_: Throwable) {
                } finally {
                    done.countDown()
                }
            }
            t.isDaemon = true
            t.start()

            // 等待，超时就强杀
            if (!done.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                sb.append("\n[GuardX] 命令超时（${timeoutMs}ms）")
                try { process.destroyForcibly() } catch (_: Throwable) {}
            }
        } catch (e: Throwable) {
            sb.append("[GuardX] root 执行失败: ").append(e.message)
        } finally {
            try { process?.destroy() } catch (_: Throwable) {}
        }
        return sb.toString()
    }

    /**
     * 执行 root 命令（不关心输出，只关心结果），用于删除等操作。
     */
    fun execQuiet(cmd: String, timeoutMs: Long = 8000): Boolean {
        return try {
            val p = ProcessBuilder("su", "-c", cmd).start()
            val ok = p.waitFor(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)
            if (!ok) { try { p.destroyForcibly() } catch (_: Throwable) {}; false } else p.exitValue() == 0
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * 用 root 删除文件/目录。
     */
    fun delete(path: String): Boolean {
        val esc = path.replace("'", "'\\''")
        return execQuiet("rm -rf '$esc'")
    }

    // ============================================================
    // 进程溯源：谁在动文件？
    // 思路：遍历 /proc/<pid>/
    //   1) 读 /proc/<pid>/cmdline 拿到进程名
    //   2) 读 /proc/<pid>/fd/* 看它是否持有该路径（或该路径的父目录）的 fd
    //   3) 用 uid 反查包名
    // 注意：这是"尽力而为"的溯源，查不到就如实返回 null，绝不编造。
    // ============================================================

    data class ProcInfo(
        val pid: Int,
        val name: String,
        val uid: Int?
    )

    /**
     * 查找持有指定路径（或其父目录）文件描述符的进程。
     * 用于判断"是谁在写这个目录"。
     */
    fun findProcessTouching(path: String): ProcInfo? {
        val parent = path.substringBeforeLast('/', path)
        try {
            val out = exec(
                "for p in /proc/[0-9]*; do " +
                "  pid=\${p#/proc/}; " +
                "  if ls -l \$p/fd/ 2>/dev/null | grep -qF -- \"$parent\"; then " +
                "    echo \"\$pid|\$(tr '\\0' ' ' < \$p/cmdline 2>/dev/null)\"; " +
                "  fi; " +
                "done",
                8000
            )
            for (line in out.lines()) {
                if (line.isBlank() || line.contains("[GuardX]")) continue
                val parts = line.split("|", limit = 2)
                if (parts.size < 2) continue
                val pid = parts[0].trim().toIntOrNull() ?: continue
                val name = parts[1].trim().ifBlank { "(未知)" }
                // 反查 uid
                val uidOut = exec("cat /proc/$pid/status 2>/dev/null | grep -m1 '^Uid:'", 4000)
                val uid = uidOut.substringAfter("Uid:", "")
                    .trim().split(Regex("\\s+")).firstOrNull()?.toIntOrNull()
                return ProcInfo(pid, name, uid)
            }
        } catch (_: Throwable) {
        }
        return null
    }

    /**
     * 用 uid 反查已安装应用包名（多包时返回第一个）。
     */
    fun packageForUid(uid: Int?): String? {
        if (uid == null) return null
        return try {
            val out = exec("pm list packages --uid $uid 2>/dev/null", 6000)
            out.lines()
                .firstOrNull { it.startsWith("package:") }
                ?.removePrefix("package:")
                ?.trim()
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * 综合溯源：返回 (进程名, 包名) 的描述文本。
     * 查不到就返回 "未知来源"。
     */
    fun attribute(path: String): String {
        val proc = findProcessTouching(path) ?: return "未知来源"
        val pkg = packageForUid(proc.uid)
        val name = proc.name.take(60)
        return if (pkg != null && !name.contains(pkg)) {
            "$name  (包名: $pkg, PID ${proc.pid})"
        } else {
            "$name  (PID ${proc.pid})"
        }
    }
}