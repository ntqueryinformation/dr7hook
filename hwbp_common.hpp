// =============================================================================
//  hwbp_common.hpp - debug register (DR7) encoding shared by both engines.
//
//  FOR AUTHORIZED SECURITY RESEARCH / EDUCATION ONLY - use on systems you own
//  or are explicitly permitted to test.
//
//  x64 Windows only.
// =============================================================================
#pragma once

#include <cstdint>

namespace hwbp {

// Breakpoint condition. The enum values intentionally match the DR7 RW field
// encoding: 0 = instruction execution, 1 = data write, 3 = data read/write.
// (RW=2 is I/O port access, only meaningful with CR4.DE and never needed here.)
enum class BreakType : uint8_t {
    Execute = 0,
    Write   = 1,
    Access  = 3,
};

static_assert(static_cast<uint8_t>(BreakType::Execute) == 0 &&
                  static_cast<uint8_t>(BreakType::Write) == 1 &&
                  static_cast<uint8_t>(BreakType::Access) == 3,
              "enum values must match the DR7 RW field encoding");

inline constexpr uint32_t kMaxBreakpoints = 4;        // DR0-DR3
inline constexpr uint64_t kDr7ReservedBit = 1ull << 10;  // RA1: must read back as 1

// DR7 LEN field encoding: 00=1 byte, 01=2 bytes, 10=8 bytes, 11=4 bytes.
// Instruction (execute) breakpoints must always be 1 byte wide.
inline bool encode_length_bits(BreakType type, uint8_t length, uint8_t* bits) {
    if (type == BreakType::Execute) {
        *bits = 0;
        return length == 1;
    }
    switch (length) {
        case 1: *bits = 0; return true;
        case 2: *bits = 1; return true;
        case 4: *bits = 3; return true;
        case 8: *bits = 2; return true;
        default: return false;
    }
}

inline bool length_supported(BreakType type, uint8_t length) {
    uint8_t bits = 0;
    return encode_length_bits(type, length, &bits);
}

// Data breakpoints require the watched address to be aligned to the watch
// window size, otherwise the CPU raises #GP instead of #DB.
inline bool address_aligned(uint64_t address, BreakType type, uint8_t length) {
    if (type == BreakType::Execute || length <= 1) return true;
    return (address % length) == 0;
}

// Merge one slot's config into DR7: RW+LEN occupy bits 16+4*slot (RW first),
// and we set both the local-enable (L#) and global-enable (G#) bits for the
// slot so the breakpoint survives regardless of how the OS toggles L/G.
inline uint64_t dr7_enable_slot(uint64_t dr7, uint32_t slot, BreakType type, uint8_t length) {
    uint8_t len_bits = 0;
    encode_length_bits(type, length, &len_bits);
    const uint32_t shift = 16 + 4 * slot;
    dr7 &= ~(0xFull << shift);  // clear old RW|LEN
    dr7 |= (static_cast<uint64_t>(static_cast<uint8_t>(type) & 3) |
            (static_cast<uint64_t>(len_bits) << 2))
           << shift;
    dr7 |= 0b11ull << (2 * slot);
    dr7 |= kDr7ReservedBit;
    return dr7;
}

inline uint64_t dr7_disable_slot(uint64_t dr7, uint32_t slot) {
    dr7 &= ~(0b11ull << (2 * slot));
    dr7 &= ~(0xFull << (16 + 4 * slot));
    return dr7;
}

}  // namespace hwbp
