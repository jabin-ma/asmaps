//
// Created by jabin on 2022/11/26.
//

#ifndef ANDROIDEXECUTABLE_MEMINFO_H
#define ANDROIDEXECUTABLE_MEMINFO_H

#include <cstring>
#include <sys/types.h>
#include <string>



struct MapInfo {
    uint64_t start;
    uint64_t end;
    uint16_t flags;
    uint64_t pgoff;
    ino_t inode;
    std::string name;
    bool shared;

    MapInfo(uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff, ino_t inode,
            const char* name, bool shared)
            : start(start),
              end(end),
              flags(flags),
              pgoff(pgoff),
              inode(inode),
              name(name),
              shared(shared) {}

    MapInfo(const MapInfo& params)
            : start(params.start),
              end(params.end),
              flags(params.flags),
              pgoff(params.pgoff),
              inode(params.inode),
              name(params.name),
              shared(params.shared) {}
};

struct MemUsage {
    uint64_t vss;
    uint64_t rss;
    uint64_t pss;
    uint64_t uss;

    uint64_t swap;
    uint64_t swap_pss;

    uint64_t private_clean;
    uint64_t private_dirty;
    uint64_t shared_clean;
    uint64_t shared_dirty;

    uint64_t anon_huge_pages;
    uint64_t shmem_pmd_mapped;
    uint64_t file_pmd_mapped;
    uint64_t shared_hugetlb;
    uint64_t private_hugetlb;

    uint64_t thp;

    MemUsage()
            : vss(0),
              rss(0),
              pss(0),
              uss(0),
              swap(0),
              swap_pss(0),
              private_clean(0),
              private_dirty(0),
              shared_clean(0),
              shared_dirty(0),
              anon_huge_pages(0),
              shmem_pmd_mapped(0),
              file_pmd_mapped(0),
              shared_hugetlb(0),
              private_hugetlb(0),
              thp(0) {}

    ~MemUsage() = default;

    void clear() {
        vss = rss = pss = uss = swap = swap_pss = 0;
        private_clean = private_dirty = shared_clean = shared_dirty = 0;
    }
};

struct Vma {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint16_t flags;
    std::string name;
    uint64_t inode;
    bool is_shared;

    Vma() : start(0), end(0), offset(0), flags(0), name(""), inode(0), is_shared(false) {}

    Vma(uint64_t s, uint64_t e, uint64_t off, uint16_t f, std::string n,
        uint64_t iNode, bool is_shared)
            : start(s), end(e), offset(off), flags(f), name(std::move(n)), inode(iNode), is_shared(is_shared) {}

    ~Vma() = default;

    void clear() { memset(&usage, 0, sizeof(usage)); }

    // Memory usage of this mapping.
    MemUsage usage;
};
using VmaCallback = std::function<void(const Vma&)>;
typedef std::function<void(const MapInfo&)> MapInfoCallback;
bool ForEachVmaFromFile(const std::string& path, const VmaCallback& callback,
                        bool read_smaps_fields = true);
#endif //ANDROIDEXECUTABLE_MEMINFO_H
