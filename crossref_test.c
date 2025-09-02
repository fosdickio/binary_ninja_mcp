// Build suggestions (macOS/Linux, x86_64):
//   clang -g -O0 -fno-inline -o crossref_test examples/crossref_test.c
// Load the resulting binary in Binary Ninja to exercise MCP xref tools.

#include <stdint.h>
#include <stddef.h>

// --- Enum for testing get_xrefs_to_enum("coff_characteristics") ---
typedef enum coff_characteristics {
    COFF_RELOCS_STRIPPED      = 0x0001,
    COFF_EXECUTABLE_IMAGE     = 0x0002,
    COFF_LINE_NUMS_STRIPPED   = 0x0004,
    COFF_LARGE_ADDRESS_AWARE  = 0x0020,
} coff_characteristics;

// --- Structs for testing get_xrefs_to_struct / get_xrefs_to_field ---
typedef struct COFF_Header {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
} COFF_Header;

typedef struct PE64_Optional_Header {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint64_t ImageBase;
} PE64_Optional_Header;

typedef struct IMAGE_NT_HEADERS64 {
    uint32_t            Signature;
    COFF_Header         FileHeader;        // alias test for COFF_Header/IMAGE_FILE_HEADER
    PE64_Optional_Header OptionalHeader;   // alias test for PE64_Optional_Header/IMAGE_OPTIONAL_HEADER64
} IMAGE_NT_HEADERS64;

// --- Union for testing get_xrefs_to_union ---
typedef union NumberU {
    int         i;
    float       f;
    int64_t     ll;
    char        bytes[8];
} NumberU;

// --- Globals to produce data/code refs ---
volatile int g_magic = 42;                 // for get_xrefs_to(address)
COFF_Header g_coff = {0};                  // for struct data refs
PE64_Optional_Header g_opt = {0};          // for struct data refs
IMAGE_NT_HEADERS64 g_nt = {0};             // contains both FileHeader and OptionalHeader
NumberU g_num;                             // for union refs

static void touch(volatile int *p) { if (p) *p += 1; }

// --- Functions that create xrefs to enum values ---
int use_enum_direct(int flags) {
    // bit-test and value combinations should yield HLIL with the immediates
    if (flags & COFF_RELOCS_STRIPPED)
        return 1;
    if (flags & COFF_EXECUTABLE_IMAGE)
        return 2;
    return 0;
}

int use_enum_build(void) {
    int flags = COFF_RELOCS_STRIPPED | COFF_LARGE_ADDRESS_AWARE;
    return use_enum_direct(flags);
}

// --- Struct/field xrefs: address-of members, casts, and variable types ---
uint64_t read_optional_imagebase_addr_of(void) {
    // Take the address of a nested field to generate a code ref to field address
    volatile uint64_t *p = &g_nt.OptionalHeader.ImageBase;
    return *p;
}

uint16_t inc_coff_sections(void) {
    // Address-of direct struct member
    volatile uint16_t *p = &g_coff.NumberOfSections;
    if (p) return (uint16_t)(*p + 1);
    return 0;
}

int parse_optional_header(void *base, size_t off) {
    // Cast to PE64_Optional_Header* to create HLIL cast text
    PE64_Optional_Header *opt = (PE64_Optional_Header *)((char*)base + off);
    if (opt->ImageBase)
        return 1;
    return 0;
}

void struct_locals(void) {
    // Local variables typed as our structs
    COFF_Header localCoff = {0};
    PE64_Optional_Header localOpt = {0};
    // Use to keep them live
    touch((volatile int *)&localCoff.NumberOfSections);
    touch((volatile int *)&localOpt.Magic);
}

// --- Union xrefs: member access and locals ---
int union_demo_set_i(int v) {
    g_num.i = v;
    return g_num.i;
}

float union_demo_set_f(float v) {
    g_num.f = v;
    return g_num.f;
}

void union_locals(void) {
    NumberU u;
    u.ll = 0x1122334455667788LL;
    if (u.bytes[0])
        touch(&g_magic);
}

// --- Address-based xref target ---
void bump_magic(void) {
    // Create explicit refs to global data address
    touch(&g_magic);
}

int main(int argc, char **argv) {
    (void)argv;
    use_enum_build();
    read_optional_imagebase_addr_of();
    inc_coff_sections();
    struct_locals();
    union_demo_set_i(argc);
    union_demo_set_f(3.14f);
    union_locals();
    bump_magic();
    // Exercise parse path with a fake buffer/offset
    char buf[256] = {0};
    parse_optional_header(buf, 64);
    return 0;
}

