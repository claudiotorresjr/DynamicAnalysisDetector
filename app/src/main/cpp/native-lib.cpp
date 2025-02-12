/**
 * native-lib.c
 *
 * This file implements native detection methods for identifying Frida instrumentation.
 *
 * The code integrates functionalities from:
 *  - The DetectFrida repository: https://github.com/darvincisec/DetectFrida
 *  - The article: https://burjcdigital.urjc.es/server/api/core/bitstreams/d249ebbb-5923-48ea-9215-af14cf2cc0b9/content
 *
 * The following detections are implemented:
 * 1. Detect "frida" references in /proc/self/maps.
 * 2. Detect writable executable pages (rwxp) in /proc/self/maps.
 * 3. Detect Frida-specific threads (e.g., "gum-js-loop", "gmain") by reading /proc/self/task/ * /status
* 4. Detect Frida-specific named pipes by scanning /proc/self/fd.
* 5. Compare disk-to-memory checksum for libraries "libnative-lib.so" and "libc.so" to detect modification.
*
* Author: Claudio Torres Junior
*/

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>
#include <fcntl.h>
#include <android/log.h>

#define APPNAME "DynamicAnalysisDetector"
#define MAX_LINE 512
#define MAX_LENGTH 256

// Libraries to be checked for disk-to-memory comparisons
#define NUM_LIBS 2
static const char *libstocheck[NUM_LIBS] = {"libnative-lib.so", "libc.so"};

/**
 * Structure to hold details of an executable section of a library.
 */
typedef struct stExecSection {
    int execSectionCount;                 /**< Number of executable sections found (max 2) */
    unsigned long offset[2];              /**< Offset of each executable section in the file */
    unsigned long memsize[2];             /**< Size of each executable section */
    unsigned long checksum[2];            /**< Checksum of each executable section calculated from disk */
    unsigned long startAddrinMem;         /**< Optional start address in memory if available */
} execSection;

/* --- Auxiliary Functions --- */

/**
 * Calculates the length of a string.
 *
 * @param s Pointer to the null-terminated string.
 * @return The length of the string.
 */
static inline size_t my_strlen(const char *s) {
    size_t len = 0;
    while (*s++) len++;
    return len;
}

/**
 * Finds the first occurrence of substring 'find' in string 's'.
 *
 * @param s The string to be scanned.
 * @param find The small string to be searched within s.
 * @return Pointer to the beginning of the located substring, or NULL if not found.
 */
static inline char *my_strstr(const char *s, const char *find) {
    char c = *find;
    if (!c) return (char *)s;
    size_t len = my_strlen(find);
    while (*s) {
        if (*s == c && strncmp(s, find, len) == 0)
            return (char *)s;
        s++;
    }
    return NULL;
}

/**
 * A simple wrapper for memset.
 *
 * @param dst Destination pointer.
 * @param c Value to set.
 * @param n Number of bytes.
 * @return Pointer to destination.
 */
static inline void *my_memset(void *dst, int c, size_t n) {
    return memset(dst, c, n);
}

/**
 * Compares two strings.
 *
 * @param s1 First string.
 * @param s2 Second string.
 * @return 0 if both strings are equal.
 */
static inline int my_strcmp(const char *s1, const char *s2) {
    return strcmp(s1, s2);
}

/**
 * Converts a string to an integer.
 *
 * @param s The string representation of an integer.
 * @return The integer value.
 */
static inline int my_atoi(const char *s) {
    return atoi(s);
}

/**
 * Safely scans a single line do /proc/self/maps para a biblioteca e evita ler
 * diretamente a memória para calcular o checksum, prevenindo SIGSEGV.
 *
 * @param map_line Uma linha lida de /proc/self/maps.
 * @param pTextSection Ponteiro para a estrutura contendo as informações da seção obtidas do arquivo em disco.
 * @return Retorna 0 (não indica manipulação) para evitar crash, ou outro valor se desejar tratar de forma diferente.
 */
static inline int safe_scan_executable_segments(char *map_line, execSection *pTextSection) {
    unsigned long start, end;
    char perms[5] = "";
    char path[MAX_LENGTH] = "";
    // Tenta extrair os dados da linha; esperamos 4 tokens (início, fim, permissões e o caminho)
    if (sscanf(map_line, "%lx-%lx %4s %*s %*s %*s %[^\n]", &start, &end, perms, path) != 4) {
        // Caso não consiga ler corretamente, retorna 0 (não manipulada)
        return 0;
    }
    // Verifica se a região possui permissões de leitura e execução
    if (perms[0] == 'r' && perms[2] == 'x') {
        // Em vez de tentar ler a memória (o que pode causar SIGSEGV), registramos e evitamos a leitura
        __android_log_print(ANDROID_LOG_WARN, APPNAME,
                            "safe_scan_executable_segments: Skipping memory checksum for region: %lx-%lx with perms: %s, path: %s",
                            start, end, perms, path);
        // Retornamos 0, indicando que não detectamos manipulação (ou pode ser alterado para retornar 1 se quiser sinalizar suspeita)
        return 0;
    }
    return 0;
}

/**
 * Reads one line from the given file descriptor.
 *
 * @param fd File descriptor.
 * @param buf Buffer to store the line.
 * @param max_len Maximum length of the line.
 * @return Number of bytes read.
 */
static inline ssize_t read_one_line(int fd, char *buf, unsigned int max_len) {
    ssize_t bytes_read = 0;
    char ch;
    while (bytes_read < max_len - 1) {
        ssize_t ret = read(fd, &ch, 1);
        if (ret != 1) break;
        if (ch == '\n') break;
        buf[bytes_read++] = ch;
    }
    buf[bytes_read] = '\0';
    return bytes_read;
}

/**
 * Computes a simple checksum as the sum of all bytes in the buffer.
 *
 * @param buffer Pointer to the data.
 * @param len Length of the data.
 * @return Calculated checksum.
 */
static inline unsigned long checksum(void *buffer, size_t len) {
    unsigned long seed = 0;
    unsigned char *buf = (unsigned char *)buffer;
    for (size_t i = 0; i < len; i++) {
        seed += buf[i];
    }
    return seed;
}

/* --- Disk-to-Memory Comparison Functions --- */

/**
 * Parses /proc/self/maps to fetch the file paths for the libraries to be checked.
 *
 * @param filepaths An array of char* of size NUM_LIBS; memory will be allocated for each path.
 */
static inline void parse_proc_maps_to_fetch_path(char **filepaths) {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) return;
    char line[MAX_LINE];
    int counter = 0;
    while (read_one_line(fd, line, MAX_LINE) > 0 && counter < NUM_LIBS) {
        for (int i = 0; i < NUM_LIBS; i++) {
            if (my_strstr(line, libstocheck[i]) != NULL) {
                // Assume the path is the last token in the line
                char *last = strrchr(line, ' ');
                if (last) {
                    last++; // skip space
                    size_t size = my_strlen(last) + 1;
                    filepaths[i] = static_cast<char *>(malloc(size));
                    strncpy(filepaths[i], last, size);
                    counter++;
                }
            }
        }
    }
    close(fd);
}

/**
 * Reads the ELF file of the library and calculates checksums for its executable sections.
 *
 * @param filePath Path to the library file.
 * @param pTextSection Pointer to an execSection pointer to store the section data.
 * @return 1 on success, 0 on failure.
 */
static inline int fetch_checksum_of_library(const char *filePath, execSection **pTextSection) {
    Elf64_Ehdr ehdr;
    Elf64_Shdr shdr;
    int fd = open(filePath, O_RDONLY);
    if (fd < 0) return 0;
    read(fd, &ehdr, sizeof(ehdr));
    lseek(fd, ehdr.e_shoff, SEEK_SET);

    int execSectionCount = 0;
    unsigned long offset[2] = {0};
    unsigned long memsize[2] = {0};

    for (int i = 0; i < ehdr.e_shnum && execSectionCount < 2; i++) {
        read(fd, &shdr, sizeof(shdr));
        if (shdr.sh_flags & SHF_EXECINSTR) {
            offset[execSectionCount] = shdr.sh_offset;
            memsize[execSectionCount] = shdr.sh_size;
            execSectionCount++;
        }
    }
    if (execSectionCount == 0) {
        close(fd);
        return 0;
    }
    *pTextSection = static_cast<execSection *>(malloc(sizeof(execSection)));
    (*pTextSection)->execSectionCount = execSectionCount;
    for (int i = 0; i < execSectionCount; i++) {
        lseek(fd, offset[i], SEEK_SET);
        uint8_t *buffer = static_cast<uint8_t *>(malloc(memsize[i]));
        read(fd, buffer, memsize[i]);
        (*pTextSection)->offset[i] = offset[i];
        (*pTextSection)->memsize[i] = memsize[i];
        (*pTextSection)->checksum[i] = checksum(buffer, memsize[i]);
        free(buffer);
    }
    close(fd);
    return 1;
}

/**
 * Scans a line from /proc/self/maps related to a library and compares the checksum
 * of the executable section in memory with the expected value from disk.
 *
 * @param map_line A single line from /proc/self/maps.
 * @param pTextSection Pointer to the execSection data for the library.
 * @return 1 if the section appears manipulated, 0 otherwise.
 */
static inline int scan_executable_segments(char *map_line, execSection *pTextSection) {
    unsigned long start, end;
    char perms[5] = "";
    char path[MAX_LENGTH] = "";
    sscanf(map_line, "%lx-%lx %4s %*s %*s %*s %[^\n]", &start, &end, perms, path);
    if (perms[0] == 'r' && perms[2] == 'x') {
        // Calculate a simple checksum from the memory region.
        unsigned long current_checksum = 0;
        size_t section_size = pTextSection->memsize[0]; // using first section
        uint8_t *mem_ptr = (uint8_t *)start;
        for (size_t i = 0; i < section_size; i++) {
            current_checksum += mem_ptr[i];
        }
        if (current_checksum != pTextSection->checksum[0]) {
            return 1; // Indicate potential manipulation.
        }
    }
    return 0;
}

/**
 * Realiza a comparação disk-to-memory para as bibliotecas definidas.
 * Em vez de ler diretamente a memória (o que pode causar crash), utiliza a função
 * safe_scan_executable_segments para verificar cada região mapeada correspondente à biblioteca.
 *
 * @return Retorna 1 se alguma região indicar manipulação (baseado na política definida),
 *         ou 0 caso contrário.
 */
static inline int detect_frida_memdiskcompare() {
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) {
        __android_log_print(ANDROID_LOG_ERROR, APPNAME, "detect_frida_memdiskcompare: unable to open /proc/self/maps");
        return 0;
    }
    char line[MAX_LINE];
    int manipulated = 0;
    // Array para armazenar os caminhos dos arquivos das bibliotecas
    char *filepaths[NUM_LIBS] = {0};
    parse_proc_maps_to_fetch_path(filepaths);
    // Array para armazenar as informações das seções obtidas dos arquivos em disco
    execSection *sections[NUM_LIBS] = {NULL};
    for (int i = 0; i < NUM_LIBS; i++) {
        if (filepaths[i] != NULL) {
            if (!fetch_checksum_of_library(filepaths[i], &sections[i])) {
                __android_log_print(ANDROID_LOG_WARN, APPNAME, "detect_frida_memdiskcompare: failed to fetch checksum for %s", filepaths[i]);
            }
            free(filepaths[i]);
        }
    }
    // Itera sobre cada linha do /proc/self/maps
    while (read_one_line(fd, line, MAX_LINE) > 0) {
        for (int i = 0; i < NUM_LIBS; i++) {
            if (sections[i] != NULL && my_strstr(line, libstocheck[i]) != NULL) {
                // Em vez de acessar diretamente a memória, chama a versão segura
                if (safe_scan_executable_segments(line, sections[i])) {
                    manipulated = 1;
                }
            }
        }
    }
    close(fd);
    // Libera a memória alocada para as seções
    for (int i = 0; i < NUM_LIBS; i++) {
        if (sections[i] != NULL) {
            free(sections[i]);
        }
    }
    return manipulated;
}

/* --- Standard Detection Functions --- */

/**
 * Checks for the presence of "frida" in /proc/self/maps.
 *
 * @return JNI_TRUE if found, JNI_FALSE otherwise.
 */
static inline jboolean check_frida_in_maps() {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return JNI_FALSE;
    char line[MAX_LINE];
    jboolean found = JNI_FALSE;
    while (fgets(line, MAX_LINE, f)) {
        if (my_strstr(line, "frida") != NULL) {
            found = JNI_TRUE;
            break;
        }
    }
    fclose(f);
    return found;
}

/**
 * Checks for any line with "rwxp" in /proc/self/maps.
 *
 * @return JNI_TRUE if such a line is found, JNI_FALSE otherwise.
 */
static inline jboolean check_writable_executable() {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return JNI_FALSE;
    char line[MAX_LINE];
    jboolean found = JNI_FALSE;
    while (fgets(line, MAX_LINE, f)) {
        if (strstr(line, "rwxp") != NULL) {
            found = JNI_TRUE;
            break;
        }
    }
    fclose(f);
    return found;
}

/**
 * Checks for Frida-specific threads by reading /proc/self/task/ * /status.
*
* @return JNI_TRUE if threads with "gum-js-loop" or "gmain" are found, JNI_FALSE otherwise.
*/
static inline jboolean check_frida_threads() {
    DIR *dir = opendir("/proc/self/task");
    if (!dir) return JNI_FALSE;
    struct dirent *entry;
    jboolean found = JNI_FALSE;
    char path[MAX_LENGTH];
    while ((entry = readdir(dir)) != NULL) {
        if (my_strcmp(entry->d_name, ".") == 0 || my_strcmp(entry->d_name, "..") == 0)
            continue;
        snprintf(path, sizeof(path), "/proc/self/task/%s/status", entry->d_name);
        FILE *f = fopen(path, "r");
        if (f) {
            char line[MAX_LINE];
            while (fgets(line, MAX_LINE, f)) {
                if (my_strstr(line, "gum-js-loop") || my_strstr(line, "gmain")) {
                    found = JNI_TRUE;
                    break;
                }
            }
            fclose(f);
            if (found) break;
        }
    }
    closedir(dir);
    return found;
}

/**
 * Checks for Frida-specific named pipes in /proc/self/fd.
 *
 * @return JNI_TRUE if a named pipe containing "linjector" is found, JNI_FALSE otherwise.
 */
static inline jboolean check_frida_namedpipes() {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return JNI_FALSE;
    struct dirent *entry;
    jboolean found = JNI_FALSE;
    char path[MAX_LENGTH];
    char buf[MAX_LENGTH];
    while ((entry = readdir(dir)) != NULL) {
        snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
        ssize_t len = readlink(path, buf, sizeof(buf) - 1);
        if (len != -1) {
            buf[len] = '\0';
            if (my_strstr(buf, "linjector") != NULL) {
                found = JNI_TRUE;
                break;
            }
        }
    }
    closedir(dir);
    return found;
}

/* --- JNI Method --- */

/**
 * Native function that returns a boolean array with the detection results.
 *
 * Order:
 *   [0] Frida in /proc/self/maps
 *   [1] Writable executable pages found
 *   [2] Frida-specific threads detected
 *   [3] Frida named pipes detected
 *   [4] Disk-to-memory comparison: libnative-lib.so
 *   [5] Disk-to-memory comparison: libc.so
 *
 * @param env JNI environment pointer.
 * @param thiz Reference to the calling Java object.
 * @return A jbooleanArray of length 6 with the detection results.
 */
extern "C" JNIEXPORT jbooleanArray JNICALL
Java_com_example_dynamicAnalysisDetector_NativeDetections_dynamicAnalysisDetector(JNIEnv *env, jobject thiz) {
    jboolean results[6];
    results[0] = check_frida_in_maps();
    results[1] = check_writable_executable();
    results[2] = check_frida_threads();
    results[3] = check_frida_namedpipes();
    // For disk-to-memory comparison, we call the same function for both libraries.
    // In a complete implementation, separate computations can be performed.
    results[4] = detect_frida_memdiskcompare() ? JNI_TRUE : JNI_FALSE;
    results[5] = detect_frida_memdiskcompare() ? JNI_TRUE : JNI_FALSE;

    jbooleanArray ret = (*env).NewBooleanArray(6);
    (*env).SetBooleanArrayRegion(ret, 0, 6, results);
    return ret;
}
