package com.example.dynamicAnalysisDetector

/**
 * Object that provides native detection methods.
 */
object NativeDetections {
    init {
        // Carrega a biblioteca nativa
        System.loadLibrary("native-lib")
    }

    /**
     * Native function that returns a BooleanArray with 6 results.
     * Order:
     * [0] Frida in /proc/self/maps
     * [1] Writable executable pages found
     * [2] Frida-specific threads detected
     * [3] Frida named pipes detected
     * [4] Disk-to-memory comparison: libnative-lib.so
     * [5] Disk-to-memory comparison: libc.so
     *
     * @return BooleanArray de tamanho 6.
     */
    external fun dynamicAnalysisDetector(): BooleanArray
}
