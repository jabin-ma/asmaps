#include "meminfo.h"
#include "sys/mman.h"
#include "iostream"

//
// Created by jabin on 2022/11/26.
//
// Returns true if the line was valid smaps stats line false otherwise.
static bool parse_smaps_field(const char* line, MemUsage* stats) {
    const char *end = line;

    // https://lore.kernel.org/patchwork/patch/1088579/ introduced tabs. Handle this case as well.
    while (*end && !isspace(*end)) end++;
    if (*end && end > line && *(end - 1) == ':') {
        const char* c = end;
        while (isspace(*c)) c++;
        switch (line[0]) {
            case 'P':
                if (strncmp(line, "Pss:", 4) == 0) {
                    stats->pss = strtoull(c, nullptr, 10);
                } else if (strncmp(line, "Private_Clean:", 14) == 0) {
                    uint64_t prcl = strtoull(c, nullptr, 10);
                    stats->private_clean = prcl;
                    stats->uss += prcl;
                } else if (strncmp(line, "Private_Dirty:", 14) == 0) {
                    uint64_t prdi = strtoull(c, nullptr, 10);
                    stats->private_dirty = prdi;
                    stats->uss += prdi;
                } else if (strncmp(line, "Private_Hugetlb:", 16) == 0) {
                    stats->private_hugetlb = strtoull(c, nullptr, 10);
                }
                break;
            case 'S':
                if (strncmp(line, "Size:", 5) == 0) {
                    stats->vss = strtoull(c, nullptr, 10);
                } else if (strncmp(line, "Shared_Clean:", 13) == 0) {
                    stats->shared_clean = strtoull(c, nullptr, 10);
                } else if (strncmp(line, "Shared_Dirty:", 13) == 0) {
                    stats->shared_dirty = strtoull(c, nullptr, 10);
                } else if (strncmp(line, "Swap:", 5) == 0) {
                    stats->swap = strtoull(c, nullptr, 10);
                } else if (strncmp(line, "SwapPss:", 8) == 0) {
                    stats->swap_pss = strtoull(c, nullptr, 10);
                } else if (strncmp(line, "ShmemPmdMapped:", 15) == 0) {
                    stats->shmem_pmd_mapped = strtoull(c, nullptr, 10);
                } else if (strncmp(line, "Shared_Hugetlb:", 15) == 0) {
                    stats->shared_hugetlb = strtoull(c, nullptr, 10);
                }
                break;
            case 'R':
                if (strncmp(line, "Rss:", 4) == 0) {
                    stats->rss = strtoull(c, nullptr, 10);
                }
                break;
            case 'A':
                if (strncmp(line, "AnonHugePages:", 14) == 0) {
                    stats->anon_huge_pages = strtoull(c, nullptr, 10);
                }
                break;
            case 'F':
                if (strncmp(line, "FilePmdMapped:", 14) == 0) {
                    stats->file_pmd_mapped = strtoull(c, nullptr, 10);
                }
                break;
        }
        return true;
    }

    return false;
}

static inline bool PassSpace(char** p) {
    if (**p != ' ') {
        return false;
    }
    while (**p == ' ') {
        (*p)++;
    }
    return true;
}

static inline bool PassXdigit(char** p) {
    if (!isxdigit(**p)) {
        return false;
    }
    do {
        (*p)++;
    } while (isxdigit(**p));
    return true;
}

// Parses a line given p pointing at proc/<pid>/maps content buffer and returns true on success
// and false on failure parsing. The next end of line will be replaced by null character and the
// immediate offset after the parsed line will be returned in next_line.
//
// Example of how a parsed line look line:
// 00400000-00409000 r-xp 00000000 fc:00 426998  /usr/lib/gvfs/gvfsd-http
static inline bool ParseMapsFileLine(char* p, uint64_t& start_addr, uint64_t& end_addr, uint16_t& flags,
                                     uint64_t& pgoff, ino_t& inode, char** name, bool& shared, char** next_line) {
    // Make end of line be null
    *next_line = strchr(p, '\n');
    if (*next_line != nullptr) {
        **next_line = '\0';
        (*next_line)++;
    }

    char* end;
    // start_addr
    start_addr = strtoull(p, &end, 16);
    if (end == p || *end != '-') {
        return false;
    }
    p = end + 1;
    // end_addr
    end_addr = strtoull(p, &end, 16);
    if (end == p) {
        return false;
    }
    p = end;
    if (!PassSpace(&p)) {
        return false;
    }
    // flags
    flags = 0;
    if (*p == 'r') {
        flags |= PROT_READ;
    } else if (*p != '-') {
        return false;
    }
    p++;
    if (*p == 'w') {
        flags |= PROT_WRITE;
    } else if (*p != '-') {
        return false;
    }
    p++;
    if (*p == 'x') {
        flags |= PROT_EXEC;
    } else if (*p != '-') {
        return false;
    }
    p++;
    if (*p != 'p' && *p != 's') {
        return false;
    }
    shared = *p == 's';

    p++;
    if (!PassSpace(&p)) {
        return false;
    }
    // pgoff
    pgoff = strtoull(p, &end, 16);
    if (end == p) {
        return false;
    }
    p = end;
    if (!PassSpace(&p)) {
        return false;
    }
    // major:minor
    if (!PassXdigit(&p) || *p++ != ':' || !PassXdigit(&p) || !PassSpace(&p)) {
        return false;
    }
    // inode
    inode = strtoull(p, &end, 10);
    if (end == p) {
        return false;
    }
    p = end;

    if (*p != '\0' && !PassSpace(&p)) {
        return false;
    }

    *name = p;

    return true;
}

inline bool ReadMapFileContent(char* content, const MapInfoCallback& callback) {
    uint64_t start_addr;
    uint64_t end_addr;
    uint16_t flags;
    uint64_t pgoff;
    ino_t inode;
    char* line_start = content;
    char* next_line;
    char* name;
    bool shared;

    while (line_start != nullptr && *line_start != '\0') {
        bool parsed = ParseMapsFileLine(line_start, start_addr, end_addr, flags, pgoff,
                                        inode, &name, shared, &next_line);
        if (!parsed) {
            return false;
        }

        line_start = next_line;
        callback(MapInfo(start_addr, end_addr, flags, pgoff, inode, name, shared));
    }
    return true;
}

bool ForEachVmaFromFile(const std::string& path, const VmaCallback& callback,
                        bool read_smaps_fields) {
    auto fp = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "re"), fclose};
    if (fp == nullptr) {
        return false;
    }

    char* line = nullptr;
    bool parsing_vma = false;
    ssize_t line_len;
    size_t line_alloc = 0;
    Vma vma;
    while ((line_len = getline(&line, &line_alloc, fp.get())) > 0) {
        // Make sure the line buffer terminates like a C string for ReadMapFile
        line[line_len] = '\0';

        if (parsing_vma) {
            if (parse_smaps_field(line, &vma.usage)) {
                // This was a stats field
                continue;
            }

            // Done collecting stats, make the call back
            callback(vma);
            parsing_vma = false;
        }

        vma.clear();
        // If it has, we are looking for the vma stats
        // 00400000-00409000 r-xp 00000000 fc:00 426998  /usr/lib/gvfs/gvfsd-http
        if (!ReadMapFileContent(
                line, [&](const MapInfo& mapinfo) {
                    vma.start = mapinfo.start;
                    vma.end = mapinfo.end;
                    vma.flags = mapinfo.flags;
                    vma.offset = mapinfo.pgoff;
                    vma.name = mapinfo.name;
                    vma.inode = mapinfo.inode;
                    vma.is_shared = mapinfo.shared;
                })) {
            // free getline() managed buffer
            free(line);
            std::cout << "Failed to parse " << path;
            return false;
        }
        if (read_smaps_fields) {
            parsing_vma = true;
        } else {
            // Done collecting stats, make the call back
            callback(vma);
        }
    }

    // free getline() managed buffer
    free(line);

    if (parsing_vma) {
        callback(vma);
    }

    return true;
}