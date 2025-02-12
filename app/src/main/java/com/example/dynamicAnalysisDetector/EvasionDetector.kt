package com.example.dynamicAnalysisDetector

import android.content.Context
import android.content.pm.PackageManager
import android.hardware.Sensor
import android.hardware.SensorManager
import android.os.Build
import android.os.Debug
import android.provider.Settings
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket

data class DetectionItem(
    val category: String,
    val method: String,
    val detected: Boolean,
    val description: String
)

object EvasionDetector {
    private const val TAG = "EvasionDetector"

    // --- ROOT DETECTIONS ---
    fun detectRootFiles(): DetectionItem {
        val paths = arrayOf(
            "/system/bin/su", "/system/xbin/su", "/sbin/su",
            "/system/app/Superuser.apk", "/system/bin/busybox"
        )
        val detected = paths.any { File(it).exists() }
        val description = "Checks for common root files: ${paths.joinToString(", ")}."
        Log.d(TAG, "detectRootFiles: $detected")
        return DetectionItem("Root", "Files", detected, description)
    }

    fun detectRootProcesses(): DetectionItem {
        val processes = listOf("su", "magisk", "daemonsu")
        val detected = try {
            val output = Runtime.getRuntime().exec("ps").inputStream.bufferedReader().use { it.readText() }
            processes.any { output.contains(it) }
        } catch (e: IOException) {
            Log.e(TAG, "detectRootProcesses IOException", e)
            false
        }
        val description = "Checks for typical root processes (su, magisk, daemonsu)."
        Log.d(TAG, "detectRootProcesses: $detected")
        return DetectionItem("Root", "Processes", detected, description)
    }

    // --- MAGISK ---
    fun detectMagisk(): DetectionItem {
        val detected = File("/system/bin/magisk").exists() || File("/system/bin/magiskinit").exists()
        val description = "Checks if Magisk files exist (/system/bin/magisk, /system/bin/magiskinit)."
        Log.d(TAG, "detectMagisk: $detected")
        return DetectionItem("Magisk", "Files", detected, description)
    }

    // --- EMULATOR ---
    fun detectEmulatorFingerprint(): DetectionItem {
        val fingerprint = Build.FINGERPRINT.lowercase()
        val emulatorKeywords = listOf("generic", "sdk_gphone", "generic_x86", "generic_x86_64", "google/sdk_gphone", "dev-keys")
        val detected = emulatorKeywords.any { fingerprint.contains(it) }
        val description = "Device fingerprint: '$fingerprint'. Keywords: ${emulatorKeywords.joinToString(", ")}."
        Log.d(TAG, "detectEmulatorFingerprint: $detected - Fingerprint: $fingerprint")
        return DetectionItem("Emulator", "Fingerprint", detected, description)
    }

    fun detectEmulatorModel(): DetectionItem {
        val model = Build.MODEL.lowercase()
        val emulatorKeywords = listOf("android sdk built for", "emulator", "sdk_gphone", "google_sdk", "android emulator")
        val detected = emulatorKeywords.any { model.contains(it) }
        val description = "Device model: '$model'."
        Log.d(TAG, "detectEmulatorModel: $detected - Model: $model")
        return DetectionItem("Emulator", "Model", detected, description)
    }

    fun detectEmulatorBoard(): DetectionItem {
        val board = Build.BOARD.lowercase()
        val emulatorBoards = listOf("unknown", "goldfish", "ranchu")
        val detected = emulatorBoards.any { board.contains(it) }
        val description = "Device board: '$board'."
        Log.d(TAG, "detectEmulatorBoard: $detected - Board: $board")
        return DetectionItem("Emulator", "Board", detected, description)
    }

    fun detectEmulatorQEMU(): DetectionItem {
        val qemuPaths = listOf(
            "/dev/socket/qemud",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace",
            "/system/bin/qemu-props",
            "/dev/qemu_pipe",
            "/system/bin/qemu-system-x86_64",
            "/system/bin/qemu-system-i386"
        )
        val detected = qemuPaths.any { File(it).exists() }
        val description = "Checks for QEMU-related files: ${qemuPaths.joinToString(", ")}."
        Log.d(TAG, "detectEmulatorQEMU: $detected")
        return DetectionItem("Emulator", "QEMU Files", detected, description)
    }

    fun detectEmulatorCPUInfo(): DetectionItem {
        val detected = try {
            val cpuInfo = File("/proc/cpuinfo").readText()
            val keywords = listOf("qemu", "kvm", "goldfish", "virtual", "emulator")
            keywords.any { cpuInfo.contains(it, ignoreCase = true) }
        } catch (e: IOException) {
            Log.e(TAG, "detectEmulatorCPUInfo IOException", e)
            false
        }
        val description = "Checks /proc/cpuinfo for emulator keywords."
        Log.d(TAG, "detectEmulatorCPUInfo: $detected")
        return DetectionItem("Emulator", "CPU Info", detected, description)
    }

    // --- DEBUGGER ---
    fun detectDebuggerConnected(context: Context): DetectionItem {
        val detected = Debug.isDebuggerConnected()
        val description = "Checks if a debugger is connected via Debug.isDebuggerConnected()."
        Log.d(TAG, "detectDebuggerConnected: $detected")
        return DetectionItem("Debug", "Debugger", detected, description)
    }

    suspend fun detectDebugPort(): DetectionItem = withContext(Dispatchers.IO) {
        val ports = listOf(23946, 23947)
        var detected = false
        for (port in ports) {
            try {
                Socket().use { socket ->
                    socket.connect(InetSocketAddress("localhost", port), 500)
                }
                detected = true
                break
            } catch (e: IOException) { }
        }
        val description = "Checks if debug ports (23946, 23947) are open."
        Log.d(TAG, "detectDebugPort: $detected")
        DetectionItem("Debug", "Ports", detected, description)
    }

    // --- SANDBOX ---
    fun detectSensorAnomalies(context: Context): DetectionItem {
        val sensorManager = context.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        val sensorCount = sensorManager.getSensorList(Sensor.TYPE_ALL).size
        val expectedMinimumSensors = 3
        val detected = sensorCount < expectedMinimumSensors
        val description = "Sensor count: $sensorCount (expected > $expectedMinimumSensors)."
        Log.d(TAG, "detectSensorAnomalies: $detected - Sensor count: $sensorCount")
        return DetectionItem("Sandbox", "Sensors", detected, description)
    }

    // --- XPOSED ---
    fun detectXposedFile(): DetectionItem {
        val detected = File("/system/framework/XposedBridge.jar").exists()
        val description = "Checks if /system/framework/XposedBridge.jar exists."
        Log.d(TAG, "detectXposedFile: $detected")
        return DetectionItem("Xposed", "File", detected, description)
    }

    fun detectXposedProcess(): DetectionItem {
        val detected = try {
            val output = Runtime.getRuntime().exec("ps").inputStream.bufferedReader().use { it.readText() }
            output.contains("de.robv.android.xposed")
        } catch (e: IOException) {
            Log.e(TAG, "detectXposedProcess IOException", e)
            false
        }
        val description = "Checks for processes related to Xposed (de.robv.android.xposed)."
        Log.d(TAG, "detectXposedProcess: $detected")
        return DetectionItem("Xposed", "Process", detected, description)
    }

    // --- TRACING ---
    fun detectPtrace(): DetectionItem {
        val tracerPid = try {
            val statusContent = File("/proc/self/status").readText()
            val tracerLine = statusContent.lines().firstOrNull { it.startsWith("TracerPid:") }
            tracerLine?.substringAfter("TracerPid:")?.trim()?.toIntOrNull() ?: 0
        } catch (e: Exception) {
            Log.e(TAG, "detectPtrace Exception", e)
            0
        }
        val detected = tracerPid != 0
        val description = "Checks TracerPid in /proc/self/status. Value: $tracerPid."
        Log.d(TAG, "detectPtrace: $detected, TracerPid: $tracerPid")
        return DetectionItem("Tracing", "ptrace", detected, description)
    }

    // --- SYSTEM PROPERTIES ---
    fun detectBuildTags(): DetectionItem {
        val tags = Build.TAGS ?: ""
        val detected = tags.contains("test-keys") || tags.contains("dev-keys")
        val description = "Build.TAGS: '$tags'."
        Log.d(TAG, "detectBuildTags: $detected - tags: $tags")
        return DetectionItem("SystemProps", "Build Tags", detected, description)
    }

    fun detectRoDebuggableProperty(): DetectionItem {
        var propertyValue = ""
        var detected = false
        try {
            val process = Runtime.getRuntime().exec("getprop ro.debuggable")
            propertyValue = process.inputStream.bufferedReader().use { it.readText().trim() }
            detected = (propertyValue == "1")
        } catch (e: IOException) {
            Log.e(TAG, "detectRoDebuggableProperty: error reading getprop", e)
        }
        val description = "ro.debuggable value: '$propertyValue' (expected '0')."
        Log.d(TAG, "detectRoDebuggableProperty: $detected - value: $propertyValue")
        return DetectionItem("SystemProps", "ro.debuggable", detected, description)
    }

    fun detectLdPreload(): DetectionItem {
        val ldPreload = System.getenv("LD_PRELOAD") ?: ""
        val detected = ldPreload.isNotEmpty()
        val description = "LD_PRELOAD: '$ldPreload'."
        Log.d(TAG, "detectLdPreload: $detected - LD_PRELOAD: $ldPreload")
        return DetectionItem("RuntimeEnv", "LD_PRELOAD", detected, description)
    }

    fun detectSuspiciousMaps(): DetectionItem {
        val suspiciousLibs = listOf("frida", "substrate", "xposed", "magisk")
        var detected = false
        val descriptionBuilder = StringBuilder("Checked for: ")
        try {
            val mapsContent = File("/proc/self/maps").readText()
            for (lib in suspiciousLibs) {
                if (mapsContent.contains(lib, ignoreCase = true)) {
                    detected = true
                    descriptionBuilder.append("$lib ")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "detectSuspiciousMaps: error reading /proc/self/maps", e)
        }
        val description = if (detected) {
            "Suspicious libs found: ${descriptionBuilder.toString()}"
        } else {
            "No suspicious libs found in /proc/self/maps."
        }
        Log.d(TAG, "detectSuspiciousMaps: $detected")
        return DetectionItem("RuntimeEnv", "Maps libs", detected, description)
    }

    fun detectAdbEnabled(context: Context): DetectionItem {
        val adb = Settings.Global.getInt(context.contentResolver, Settings.Global.ADB_ENABLED, 0)
        val detected = (adb == 1)
        val description = "ADB_ENABLED: $adb."
        Log.d(TAG, "detectAdbEnabled: $detected - ADB: $adb")
        return DetectionItem("SystemProps", "ADB Enabled", detected, description)
    }

    fun detectSuspiciousPackages(context: Context): DetectionItem {
        val suspiciousPackages = listOf(
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.chaintools",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "com.yellowes.su",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot",
            "com.zhiqupk.root.global",
            "com.genymotion",
            "com.bluestacks",
            "com.mumu.store"
        )
        var detected = false
        val foundPackages = mutableListOf<String>()
        try {
            val pm = context.packageManager
            val installedApps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            for (app in installedApps) {
                val packageName = app.packageName.lowercase()
                suspiciousPackages.forEach { suspect ->
                    if (packageName.contains(suspect.lowercase())) {
                        detected = true
                        foundPackages.add(packageName)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "detectSuspiciousPackages Exception", e)
        }
        val description = if (foundPackages.isNotEmpty()) {
            "Suspicious packages: ${foundPackages.joinToString(", ")}."
        } else {
            "No suspicious packages found."
        }
        Log.d(TAG, "detectSuspiciousPackages: $detected")
        return DetectionItem("Packages", "Suspicious Apps", detected, description)
    }

    // --- FRIDA (Kotlin-based) ---
    suspend fun detectFridaFile(): DetectionItem = withContext(Dispatchers.IO) {
        val detected = File("/data/local/tmp/frida-server").exists()
        val description = "Checks if /data/local/tmp/frida-server exists."
        Log.d(TAG, "detectFridaFile: $detected")
        DetectionItem("Frida", "File", detected, description)
    }

    suspend fun detectFridaPort(): DetectionItem = withContext(Dispatchers.IO) {
        var detected = false
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("127.0.0.1", 27042), 500)
                detected = true
            }
        } catch (e: IOException) {
            detected = false
        }
        val description = "Checks if Frida port (27042) is open."
        Log.d(TAG, "detectFridaPort: $detected")
        DetectionItem("Frida", "Port", detected, description)
    }

    // --- NATIVE FRIDA DETECTIONS ---
    /**
     * Retrieves the native Frida detection results (the six items returned by the native code)
     * and returns a list of DetectionItem.
     */
    fun getNativeFridaDetections(): List<DetectionItem> {
        val nativeResults = NativeDetections.dynamicAnalysisDetector()
        // Define names and descriptions for each native detection item.
        val methods = listOf(
            "Frida in /proc/self/maps",
            "Writable Executable Pages",
            "Frida-specific Threads",
            "Frida Named Pipes",
            "Disk-to-Memory: libnative-lib.so",
            "Disk-to-Memory: libc.so"
        )
        val descriptions = listOf(
            "Checks for 'frida' in /proc/self/maps.",
            "Checks for pages with rwxp permissions.",
            "Checks for threads named 'gum-js-loop' or 'gmain'.",
            "Checks for named pipes containing 'linjector'.",
            "Compares checksum of libnative-lib.so in memory vs. disk.",
            "Compares checksum of libc.so in memory vs. disk."
        )
        val items = mutableListOf<DetectionItem>()
        for (i in methods.indices) {
            items.add(
                DetectionItem(
                    category = "Frida (Native)",
                    method = methods[i],
                    detected = if (nativeResults.size > i) nativeResults[i] else false,
                    description = descriptions[i]
                )
            )
        }
        return items
    }

    // --- AGGREGATED FUNCTION ---
    /**
     * Aggregates all detection items into a single list.
     */
    suspend fun getAllDetections(context: Context): List<DetectionItem> {
        val detections = mutableListOf<DetectionItem>()

        // Root detections
        detections.add(detectRootFiles())
        detections.add(detectRootProcesses())
        detections.add(detectMagisk())

        // Emulator detections
        detections.add(detectEmulatorFingerprint())
        detections.add(detectEmulatorModel())
        detections.add(detectEmulatorBoard())
        detections.add(detectEmulatorQEMU())
        detections.add(detectEmulatorCPUInfo())

        // Debug detections
        detections.add(detectDebuggerConnected(context))
        detections.add(detectDebugPort())

        // Sandbox
        detections.add(detectSensorAnomalies(context))

        // Xposed
        detections.add(detectXposedFile())
        detections.add(detectXposedProcess())

        // Tracing
        detections.add(detectPtrace())

        // System properties
        detections.add(detectBuildTags())
        detections.add(detectRoDebuggableProperty())
        detections.add(detectAdbEnabled(context))
        detections.add(detectLdPreload())
        detections.add(detectSuspiciousMaps())

        // Suspicious packages
        detections.add(detectSuspiciousPackages(context))

        // Frida (Kotlin)
        detections.add(detectFridaFile())
        detections.add(detectFridaPort())

        // Native Frida detections
        detections.addAll(getNativeFridaDetections())

        return detections
    }
}
