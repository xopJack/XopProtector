#pragma once

#include <elf.h>
#include <cstdint>
#include <cstdio>
#include <string>

namespace protector {

#ifdef __LP64__
using Elf_Ehdr = Elf64_Ehdr;
using Elf_Shdr = Elf64_Shdr;
using Elf_Phdr = Elf64_Phdr;
using Elf_Off = Elf64_Off;
using Elf_Word = Elf64_Word;
#else
using Elf_Ehdr = Elf32_Ehdr;
using Elf_Shdr = Elf32_Shdr;
using Elf_Phdr = Elf32_Phdr;
using Elf_Off = Elf32_Off;
using Elf_Word = Elf32_Word;
#endif

/** Resolve an absolute path for a loaded .so via /proc/self/maps. */
std::string find_so_path(const char* so_name);

/**
 * Fill target with the named ELF section header (reads headers only, not whole file).
 * On failure leaves target zeroed / unchanged size 0.
 */
void get_elf_section(Elf_Shdr* target, const char* elf_path, const char* sh_name);

/**
 * Lowest PT_LOAD p_vaddr from the on-disk ELF (0 when first LOAD is at 0).
 * Used with maps start: load_bias = map_start - p_vaddr.
 */
bool get_first_pt_load_vaddr(const char* elf_path, uint64_t* out_vaddr);

/**
 * Resolve ELF load bias for a loaded module (basename or path substring).
 * On success writes *out_bias (may be 0 when map_start == first PT_LOAD p_vaddr)
 * and returns true. On failure returns false and leaves *out_bias unchanged.
 */
bool find_so_load_bias(const char* so_name, uintptr_t* out_bias);

/**
 * One /proc/self/maps record. 4KB chunks are stitched until newline so a
 * pathname longer than 255 bytes is not split onto the next parse.
 * The stored line is capped at PATH_MAX plus the maps prefix.
 */
bool read_maps_record(FILE* fp, std::string* line);

/** Pathname after the inode field, including spaces. False if anonymous. */
bool maps_pathname(const std::string& line, std::string* path);

} // namespace protector
