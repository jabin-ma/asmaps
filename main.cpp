#include "meminfo.h"
#include <sys/system_properties.h>
#include <cstring>
#include <string>
#include <iostream>

enum {
    HEAP_UNKNOWN,
    HEAP_DALVIK,
    HEAP_NATIVE,

    HEAP_DALVIK_OTHER,
    HEAP_STACK,
    HEAP_CURSOR,
    HEAP_ASHMEM,
    HEAP_GL_DEV,
    HEAP_UNKNOWN_DEV,
    HEAP_SO,
    HEAP_JAR,
    HEAP_APK,
    HEAP_TTF,
    HEAP_DEX,
    HEAP_OAT,
    HEAP_ART,
    HEAP_UNKNOWN_MAP,
    HEAP_GRAPHICS,
    HEAP_GL,
    HEAP_OTHER_MEMTRACK,

    // Dalvik extra sections (heap).
    HEAP_DALVIK_NORMAL,
    HEAP_DALVIK_LARGE,
    HEAP_DALVIK_ZYGOTE,
    HEAP_DALVIK_NON_MOVING,

    // Dalvik other extra sections.
    HEAP_DALVIK_OTHER_LINEARALLOC,
    HEAP_DALVIK_OTHER_ACCOUNTING,
    HEAP_DALVIK_OTHER_ZYGOTE_CODE_CACHE,
    HEAP_DALVIK_OTHER_APP_CODE_CACHE,
    HEAP_DALVIK_OTHER_COMPILER_METADATA,
    HEAP_DALVIK_OTHER_INDIRECT_REFERENCE_TABLE,

    // Boot vdex / app dex / app vdex
    HEAP_DEX_BOOT_VDEX,
    HEAP_DEX_APP_DEX,
    HEAP_DEX_APP_VDEX,

    // App art, boot art.
    HEAP_ART_APP,
    HEAP_ART_BOOT,

    _NUM_HEAP,
    _NUM_EXCLUSIVE_HEAP = HEAP_OTHER_MEMTRACK+1,
    _NUM_CORE_HEAP = HEAP_NATIVE+1
};

struct stats_t {
    uint64_t pss;
    uint64_t swappablePss;
    uint64_t rss;
    uint64_t privateDirty;
    uint64_t sharedDirty;
    uint64_t privateClean;
    uint64_t sharedClean;
    uint64_t swappedOut;
    uint64_t swappedOutPss;
};
bool StartsWith(const std::string& str, const std::string prefix) {
    return (str.rfind(prefix, 0) == 0);
}

bool EndsWith(const std::string& str, const std::string suffix) {
    if (suffix.length() > str.length()) { return false; }

    return (str.rfind(suffix) == (str.length() - suffix.length()));
}

static bool load_maps(int pid, stats_t* stats, bool* foundSwapPss)
{
    *foundSwapPss = false;
    uint64_t prev_end = 0;
    int prev_heap = HEAP_UNKNOWN;

    std::string smaps_path = "/proc/self/smaps";
    auto vma_scan = [&](const Vma& vma) {
        std::cout << "VMA:"<<vma.name <<std::endl;
        int which_heap = HEAP_UNKNOWN;
        int sub_heap = HEAP_UNKNOWN;
        bool is_swappable = false;
        std::string name;
        if (EndsWith(vma.name, " (deleted)")) {
            name = vma.name.substr(0, vma.name.size() - strlen(" (deleted)"));
        } else {
            name = vma.name;
        }

        uint32_t namesz = name.size();
        if (StartsWith(name, "[heap]")) {
            which_heap = HEAP_NATIVE;
        } else if (StartsWith(name, "[anon:libc_malloc]")) {
            which_heap = HEAP_NATIVE;
        } else if (StartsWith(name, "[anon:scudo:")) {
            which_heap = HEAP_NATIVE;
        } else if (StartsWith(name, "[anon:GWP-ASan")) {
            which_heap = HEAP_NATIVE;
        } else if (StartsWith(name, "[stack")) {
            which_heap = HEAP_STACK;
        } else if (StartsWith(name, "[anon:stack_and_tls:")) {
            which_heap = HEAP_STACK;
        } else if (EndsWith(name, ".so")) {
            which_heap = HEAP_SO;
            is_swappable = true;
        } else if (EndsWith(name, ".jar")) {
            which_heap = HEAP_JAR;
            is_swappable = true;
        } else if (EndsWith(name, ".apk")) {
            which_heap = HEAP_APK;
            is_swappable = true;
        } else if (EndsWith(name, ".ttf")) {
            which_heap = HEAP_TTF;
            is_swappable = true;
        } else if ((EndsWith(name, ".odex")) ||
                   (namesz > 4 && strstr(name.c_str(), ".dex") != nullptr)) {
            which_heap = HEAP_DEX;
            sub_heap = HEAP_DEX_APP_DEX;
            is_swappable = true;
        } else if (EndsWith(name, ".vdex")) {
            which_heap = HEAP_DEX;
            // Handle system@framework@boot and system/framework/boot|apex
            if ((strstr(name.c_str(), "@boot") != nullptr) ||
                (strstr(name.c_str(), "/boot") != nullptr) ||
                (strstr(name.c_str(), "/apex") != nullptr)) {
                sub_heap = HEAP_DEX_BOOT_VDEX;
            } else {
                sub_heap = HEAP_DEX_APP_VDEX;
            }
            is_swappable = true;
        } else if (EndsWith(name, ".oat")) {
            which_heap = HEAP_OAT;
            is_swappable = true;
        } else if (EndsWith(name, ".art") || EndsWith(name, ".art]")) {
            which_heap = HEAP_ART;
            // Handle system@framework@boot* and system/framework/boot|apex*
            if ((strstr(name.c_str(), "@boot") != nullptr) ||
                (strstr(name.c_str(), "/boot") != nullptr) ||
                (strstr(name.c_str(), "/apex") != nullptr)) {
                sub_heap = HEAP_ART_BOOT;
            } else {
                sub_heap = HEAP_ART_APP;
            }
            is_swappable = true;
        } else if (StartsWith(name, "/dev/")) {
            which_heap = HEAP_UNKNOWN_DEV;
            if (StartsWith(name, "/dev/kgsl-3d0")) {
                which_heap = HEAP_GL_DEV;
            } else if (StartsWith(name, "/dev/ashmem/CursorWindow")) {
                which_heap = HEAP_CURSOR;
            } else if (StartsWith(name, "/dev/ashmem/jit-zygote-cache")) {
                which_heap = HEAP_DALVIK_OTHER;
                sub_heap = HEAP_DALVIK_OTHER_ZYGOTE_CODE_CACHE;
            } else if (StartsWith(name, "/dev/ashmem")) {
                which_heap = HEAP_ASHMEM;
            }
        } else if (StartsWith(name, "/memfd:jit-cache")) {
            which_heap = HEAP_DALVIK_OTHER;
            sub_heap = HEAP_DALVIK_OTHER_APP_CODE_CACHE;
        } else if (StartsWith(name, "/memfd:jit-zygote-cache")) {
            which_heap = HEAP_DALVIK_OTHER;
            sub_heap = HEAP_DALVIK_OTHER_ZYGOTE_CODE_CACHE;
        } else if (StartsWith(name, "[anon:")) {
            which_heap = HEAP_UNKNOWN;
            if (StartsWith(name, "[anon:dalvik-")) {
                which_heap = HEAP_DALVIK_OTHER;
                if (StartsWith(name, "[anon:dalvik-LinearAlloc")) {
                    sub_heap = HEAP_DALVIK_OTHER_LINEARALLOC;
                } else if (StartsWith(name, "[anon:dalvik-alloc space") ||
                           StartsWith(name, "[anon:dalvik-main space")) {
                    // This is the regular Dalvik heap.
                    which_heap = HEAP_DALVIK;
                    sub_heap = HEAP_DALVIK_NORMAL;
                } else if (StartsWith(name,
                                            "[anon:dalvik-large object space") ||
                           StartsWith(
                                   name, "[anon:dalvik-free list large object space")) {
                    which_heap = HEAP_DALVIK;
                    sub_heap = HEAP_DALVIK_LARGE;
                } else if (StartsWith(name, "[anon:dalvik-non moving space")) {
                    which_heap = HEAP_DALVIK;
                    sub_heap = HEAP_DALVIK_NON_MOVING;
                } else if (StartsWith(name, "[anon:dalvik-zygote space")) {
                    which_heap = HEAP_DALVIK;
                    sub_heap = HEAP_DALVIK_ZYGOTE;
                } else if (StartsWith(name, "[anon:dalvik-indirect ref")) {
                    sub_heap = HEAP_DALVIK_OTHER_INDIRECT_REFERENCE_TABLE;
                } else if (StartsWith(name, "[anon:dalvik-jit-code-cache") ||
                           StartsWith(name, "[anon:dalvik-data-code-cache")) {
                    sub_heap = HEAP_DALVIK_OTHER_APP_CODE_CACHE;
                } else if (StartsWith(name, "[anon:dalvik-CompilerMetadata")) {
                    sub_heap = HEAP_DALVIK_OTHER_COMPILER_METADATA;
                } else {
                    sub_heap = HEAP_DALVIK_OTHER_ACCOUNTING;  // Default to accounting.
                }
            }
        } else if (namesz > 0) {
            which_heap = HEAP_UNKNOWN_MAP;
        } else if (vma.start == prev_end && prev_heap == HEAP_SO) {
            // bss section of a shared library
            which_heap = HEAP_SO;
        }

        prev_end = vma.end;
        prev_heap = which_heap;

        const MemUsage& usage = vma.usage;
        if (usage.swap_pss > 0 && !*foundSwapPss) {
            *foundSwapPss = true;
        }

        uint64_t swapable_pss = 0;
        if (is_swappable && (usage.pss > 0)) {
            uint64_t sharing_proportion = 0.0;
            if ((usage.shared_clean > 0) || (usage.shared_dirty > 0)) {
                sharing_proportion = (usage.pss - usage.uss) / (usage.shared_clean + usage.shared_dirty);
            }
            swapable_pss = (sharing_proportion * usage.shared_clean) + usage.private_clean;
        }

        stats[which_heap].pss += usage.pss;
        stats[which_heap].swappablePss += swapable_pss;
        stats[which_heap].rss += usage.rss;
        stats[which_heap].privateDirty += usage.private_dirty;
        stats[which_heap].sharedDirty += usage.shared_dirty;
        stats[which_heap].privateClean += usage.private_clean;
        stats[which_heap].sharedClean += usage.shared_clean;
        stats[which_heap].swappedOut += usage.swap;
        stats[which_heap].swappedOutPss += usage.swap_pss;
        if (which_heap == HEAP_DALVIK || which_heap == HEAP_DALVIK_OTHER ||
            which_heap == HEAP_DEX || which_heap == HEAP_ART) {
            stats[sub_heap].pss += usage.pss;
            stats[sub_heap].swappablePss += swapable_pss;
            stats[sub_heap].rss += usage.rss;
            stats[sub_heap].privateDirty += usage.private_dirty;
            stats[sub_heap].sharedDirty += usage.shared_dirty;
            stats[sub_heap].privateClean += usage.private_clean;
            stats[sub_heap].sharedClean += usage.shared_clean;
            stats[sub_heap].swappedOut += usage.swap;
            stats[sub_heap].swappedOutPss += usage.swap_pss;
        }
    };

    return ForEachVmaFromFile(smaps_path, vma_scan);
}

int main(){
    bool foundSwapPss;
    stats_t stats[_NUM_HEAP];
    memset(&stats, 0, sizeof(stats));
    load_maps(0, stats, &foundSwapPss);
}