#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#pragma pack(1)
#define MAGIC 0x4c415641

enum {
    TYPEA = 1,
    TYPEB = 2
};

typedef struct {
    uint32_t magic;     // Magic value
    uint32_t reserved;  // Reserved for future use
    uint16_t num_recs;  // How many entries?
    uint16_t flags;     // None used yet
    uint32_t timestamp; // Unix Time
} file_header;

typedef struct {
    char bar[16];
    uint32_t type;
    union {
        float fdata;
        uint32_t intdata;
    } data;
} file_entry;

/* Keep mandatory header validation separate from the chaff payload. Returning
 * by value avoids exposing a header pointer parameter as an early whole-buffer
 * DUA: selecting its magic bytes as an extra would make zeroing that extra
 * reject the input before later attack points. The wire format is unchanged.
 */
file_header parse_header(FILE *f) {
    file_header hdr;
    if (1 != fread(&hdr, sizeof(file_header), 1, f))
        exit(1);
    if (hdr.magic != MAGIC)
        exit(1);
    return hdr;
}

file_entry * parse_record(FILE *f) {
    file_entry *ret = (file_entry *) malloc(sizeof(file_entry));
    if (1 != fread(ret, sizeof(file_entry), 1, f))
        exit(1);
    return ret;
}

/* Pass the complete, fread-initialized record by value. DUASan accepts value
 * parameters without inferring initialization through a pointer or callee.
 * This keeps a 24-byte input-derived buffer available for RET_BUFFER testing;
 * field reads alone do not qualify the whole pointed-to record. See Chaff Bugs
 * (2018), IV-A1 and V-B3, for the initialized-DUA requirement and scope strategy.
 */
void consume_record(file_entry ent) {
    volatile uint32_t sink_value = ent.data.intdata;
    volatile uint32_t *sink = &sink_value;
    *sink = ent.type;

    printf("Entry: bar = %.*s, ", (int)sizeof(ent.bar), ent.bar);
    if (ent.type == TYPEA) {
        printf("fdata = %f\n", ent.data.fdata);
    }
    else if (ent.type == TYPEB) {
        printf("intdata = %u\n", ent.data.intdata);
    }
    else {
        printf("Unknown type %x\n", ent.type);
    }
}

int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "rb");
    file_header head = parse_header(f);
    printf("File timestamp: %u\n", head.timestamp);

    unsigned i;
    for (i = 0; i < head.num_recs; i++) {
        file_entry *ent = parse_record(f);
        consume_record(*ent);
        free(ent);
    }
    return 0;
}
