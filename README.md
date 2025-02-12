# EvadingDynamicAnalysis

**EvadingDynamicAnalysis** is an Android application designed to demonstrate various techniques for detecting dynamic analysis and instrumentation evasion mechanisms. The project integrates detection methods implemented both in Kotlin (using standard Android APIs and Jetpack Compose for the UI) and in native code via JNI. These methods aim to identify suspicious behaviors such as root access, emulator artifacts, debugger connections, dynamic instrumentation (e.g., Frida), Xposed, and other system/environment properties.

> **Note:**  
> This project is free for anyone to use, extend, and improve. Feel free to add additional detection methods or enhance the design of the app as needed.

## Features

The application performs a comprehensive set of checks, including:

- **Root Detection:**
    - Checks for the presence of common root files (e.g., `/system/bin/su`, `/system/xbin/su`, etc.).
    - Verifies running processes that indicate root (e.g., `su`, `magisk`, `daemonsu`).
    - Detects Magisk-specific files.

- **Emulator Detection:**
    - Analyzes the device fingerprint, model, board, and CPU information to detect emulation.
    - Checks for emulator-related files (e.g., Genymotion, BlueStacks).

- **Debugger Detection:**
    - Uses `Debug.isDebuggerConnected()` to determine if a debugger is attached.
    - Checks common debug ports (e.g., 23946 and 23947).

- **Sandbox Detection:**
    - Examines sensor availability (anomalies in sensor count may indicate a sandboxed environment).

- **Xposed Detection:**
    - Detects the existence of `XposedBridge.jar` in `/system/framework`.
    - Checks for Xposed-related processes.

- **Frida Detection:**
    - **Kotlin-based checks:** Verifies the existence of the Frida server file (e.g., `/data/local/tmp/frida-server`) and whether the Frida default port (27042) is open.
    - **Native checks via JNI:**
        - Scans `/proc/self/maps` for any references to “frida”.
        - Checks for writable executable pages (rwxp) that may indicate dynamic instrumentation.
        - Detects Frida-specific threads (e.g., names like `gum-js-loop` and `gmain`).
        - Searches for suspicious named pipes.
        - Compares disk-to-memory checksums for key libraries (e.g., `libnative-lib.so` and `libc.so`) using a safe, non-crashing implementation.

- **Tracing Detection:**
    - Reads the `TracerPid` field from `/proc/self/status` to determine if the process is being traced.

- **System & Environment Properties:**
    - Examines build tags and the `ro.debuggable` property.
    - Checks for the presence of `LD_PRELOAD` in the environment.
    - Scans `/proc/self/maps` for other suspicious libraries (e.g., those related to substrate, Xposed, or Magisk).
    - Attempts to determine the SELinux enforcement status (with error handling for access denial).
    - Detects suspicious packages installed on the system.

## Build and Test Instructions

- **Building the Project:**  
  You can build this project directly in Android Studio. The project includes both Kotlin and native (C) code. The native code is built using CMake.
    - Open the project in Android Studio.
    - Sync the Gradle files.
    - Build the project by selecting **Build > Rebuild Project**.

- **Testing on Emulators:**  
  The provided APK (`dynamicAnalysisDetector.apk`) is available for testing on x86_64 emulators.
    - The app was tested on an Android Studio emulator running Android 10.
    - Install the APK on your emulator and run the app to view the detection results.

## Running the App

Upon launching the app, the main screen displays a list of detection categories grouped by type using a modern, responsive UI built with Jetpack Compose. Each category card is expandable and reveals individual detection items with icons indicating positive or negative results. A refresh button is provided to re-run all detection checks.

## References

- **Unmasking the Veiled: A Comprehensive Analysis of Android Evasive Malware**  
  [https://dl.acm.org/doi/pdf/10.1145/3634737.3637658](https://dl.acm.org/doi/pdf/10.1145/3634737.3637658)

- **Evasion Techniques in Malware Detection: Challenges and Countermeasures**  
  [https://jpit.az/uploads/article/en/2024_2/EVASION_TECHNIQUES_IN_MALWARE_DETECTION_CHALLENGES_AND_COUNTERMEASURES.pdf](https://jpit.az/uploads/article/en/2024_2/EVASION_TECHNIQUES_IN_MALWARE_DETECTION_CHALLENGES_AND_COUNTERMEASURES.pdf)

- **Detecting and Bypassing Frida Dynamic Function Call Tracing: Exploitation and Mitigation**  
  [https://burjcdigital.urjc.es/server/api/core/bitstreams/d249ebbb-5923-48ea-9215-af14cf2cc0b9/content](https://burjcdigital.urjc.es/server/api/core/bitstreams/d249ebbb-5923-48ea-9215-af14cf2cc0b9/content)

- **DetectFrida**  
  [https://github.com/darvincisec/DetectFrida](https://github.com/darvincisec/DetectFrida)

## License

This project is free for anyone to use, modify, and extend. Contributions and additional detection methods are welcome, as well as improvements to the app's design.

## Author

**Claudio Torres Junior**
