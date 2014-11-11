/*
    TODO: Bundle fragmentation is not implemented.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#include <time.h>
#include <sys/time.h>
#include "bundle.h"

#define MAX_SDNV_LENGTH 8 // Bytes
#define RFC_DATE_2000 946684800

/* sdnv_ functions from DTN2 reference implementation */
int sdnv_encode(uint64_t val, uint8_t *bp)
{
    size_t val_len = 0;
    uint64_t tmp = val;

    do
    {
        tmp = tmp >> 7;
        val_len++;
    }
    while (tmp != 0);

    bp += val_len;
    uint8_t high_bit = 0; // for the last octet
    do
    {
        --bp;
        *bp = (uint8_t)(high_bit | (val & 0x7f));
        high_bit = (1 << 7); // for all but the last octet
        val = val >> 7;
    }
    while (val != 0);

    return val_len;
}

size_t sdnv_encoding_len(uint64_t val)
{
    size_t val_len = 0;
    uint64_t tmp = val;
    do
    {
        tmp = tmp >> 7;
        val_len++;
    }
    while (tmp != 0);

    return val_len;
}

int sdnv_decode(const uint8_t *bp, uint64_t *val)
{
    const uint8_t *start = bp;
    if (!val)
    {
        return -1;
    }
    size_t val_len = 0;
    *val = 0;
    do
    {
        *val = (*val << 7) | (*bp & 0x7f);
        ++val_len;

        if ((*bp & (1 << 7)) == 0)
        {
            break; // all done;
        }

        ++bp;
    }
    while (1);

    if ((val_len > MAX_SDNV_LENGTH) || ((val_len == MAX_SDNV_LENGTH) && (*start != 0x81)))
    {
        return -1;
    }

    return val_len;
}

size_t sdnv_len(const uint8_t *bp)
{
    size_t val_len = 1;
    for ( ; *bp++ & 0x80; ++val_len );

    return val_len;
}

/**/

/* Primary Block Block RFC5050 */
bundle_s *bundle_new()
{
    bundle_s *ret = NULL;
    static int last_timestamp = 0;
    static int timestamp_seq = 0;
    time_t actual_time;

    bundle_s *new_b = (bundle_s *)calloc(1, sizeof(bundle_s));
    new_b->primary = (primary_block_s *)calloc(1, sizeof(primary_block_s));

    // Set actual timestamp avoiding duplicated timestamp/timestamp_seq pairs
    actual_time = time(NULL);
    new_b->primary->timestamp_time = actual_time - RFC_DATE_2000;
    if (new_b->primary->timestamp_time == last_timestamp)
        timestamp_seq++;
    else
        timestamp_seq = 0;
    new_b->primary->timestamp_seq = timestamp_seq;
    last_timestamp = new_b->primary->timestamp_time;

    // Defaults from RFC5050
    new_b->primary->version = PRIM_B;

    //All offsets points to the first position of the dict, wich is a NULL char.
    new_b->primary->dict_length = 1;
    new_b->primary->dict = (char *)calloc(1, new_b->primary->dict_length);

    ret = new_b;

    return ret;
}

int bundle_set_proc_flags(bundle_s *bundle, uint64_t flags)
{
    int ret = 0;

    if (!bundle)
    {
        ret = 1;
        goto end;
    }

    bundle->primary->proc_flags = bundle->primary->proc_flags | flags;

end:
    return ret;
}

int bundle_set_lifetime(bundle_s *bundle, uint64_t lifetime)
{
    int ret = 0;

    if (!bundle)
    {
        ret = 1;
        goto end;
    }

    bundle->primary->lifetime = lifetime;
end:
    return ret;
}

static int bundle_set_dict_offset(bundle_s *bundle, primary_field_e field, uint64_t offset)
{
    int ret = 0;

    if (!bundle)
    {
        ret = 1;
        goto end;
    }

    switch (field)
    {
    case DEST_SCHEME:
        bundle->primary->dest_scheme_offset = offset;
        break;
    case DEST_SSP:
        bundle->primary->dest_ssp_offset = offset;
        break;
    case SOURCE_SCHEME:
        bundle->primary->source_scheme_offset = offset;
        break;
    case SOURCE_SSP:
        bundle->primary->source_ssp_offset = offset;
        break;
    case REPORT_SCHEME:
        bundle->primary->report_scheme_offset = offset;
        break;
    case REPORT_SSP:
        bundle->primary->report_ssp_offset = offset;
        break;
    case CUST_SCHEME:
        bundle->primary->cust_scheme_offset = offset;
        break;
    case CUST_SSP:
        bundle->primary->cust_ssp_offset = offset;
        break;
    default:
        ret = 1;
    }

end:
    return ret;
}

static int bundle_get_dict_offset(bundle_s *bundle, primary_field_e field)
{
    int ret = 0;

    if (!bundle)
    {
        ret = -1;
        goto end;
    }

    switch (field)
    {
    case DEST_SCHEME:
        ret = bundle->primary->dest_scheme_offset;
        break;
    case DEST_SSP:
        ret = bundle->primary->dest_ssp_offset;
        break;
    case SOURCE_SCHEME:
        ret = bundle->primary->source_scheme_offset;
        break;
    case SOURCE_SSP:
        ret = bundle->primary->source_ssp_offset;
        break;
    case REPORT_SCHEME:
        ret = bundle->primary->report_scheme_offset;
        break;
    case REPORT_SSP:
        ret = bundle->primary->report_ssp_offset;
        break;
    case CUST_SCHEME:
        ret = bundle->primary->cust_scheme_offset;
        break;
    case CUST_SSP:
        ret = bundle->primary->cust_ssp_offset;
        break;
    default:
        ret = -1;
    }

end:
    return ret;
}

static int bundle_update_primary_offsets(bundle_s *bundle, uint64_t removed_entry_offset, int removed_entry_l)
{
    if (bundle->primary->dest_scheme_offset > removed_entry_offset)
        bundle->primary->dest_scheme_offset -= removed_entry_l;
    if (bundle->primary->dest_ssp_offset > removed_entry_offset)
        bundle->primary->dest_ssp_offset -= removed_entry_l;
    if (bundle->primary->source_scheme_offset > removed_entry_offset)
        bundle->primary->source_scheme_offset -= removed_entry_l;
    if (bundle->primary->source_ssp_offset > removed_entry_offset)
        bundle->primary->source_ssp_offset -= removed_entry_l;
    if (bundle->primary->report_scheme_offset > removed_entry_offset)
        bundle->primary->report_scheme_offset -= removed_entry_l;
    if (bundle->primary->report_ssp_offset > removed_entry_offset)
        bundle->primary->report_ssp_offset -= removed_entry_l;
    if (bundle->primary->cust_scheme_offset > removed_entry_offset)
        bundle->primary->cust_scheme_offset -= removed_entry_l;
    if (bundle->primary->cust_ssp_offset > removed_entry_offset)
        bundle->primary->cust_ssp_offset -= removed_entry_l;

    return 0;
}

static int bundle_remove_dict_entry(bundle_s *bundle, uint64_t removed_entry_offset)
{
    int removed_entry_l = 0, ret = 0, new_dict_l = 0;
    char *new_dict = NULL;

    removed_entry_l = strlen(bundle->primary->dict + removed_entry_offset) + 1;
    new_dict_l = bundle->primary->dict_length - removed_entry_l;
    new_dict = (char *)malloc(new_dict_l);

    // Before removed entry
    memcpy(new_dict, bundle->primary->dict, removed_entry_offset);
    // After removed entry
    memcpy(new_dict + removed_entry_offset, bundle->primary->dict + removed_entry_offset + removed_entry_l, bundle->primary->dict_length - removed_entry_offset - removed_entry_l);

    // Replace dictionary
    free(bundle->primary->dict);
    bundle->primary->dict = new_dict;
    bundle->primary->dict_length = new_dict_l;

    // Update offsets
    ret = bundle_update_primary_offsets(bundle, removed_entry_offset, removed_entry_l);

    return ret;
}

static int bundle_add_dict_entry(bundle_s *bundle, const char *new_dict_entry)
{
    int new_dict_entry_l = 0, entry_offset = 0, ret = 0;

    if (!bundle)
    {
        ret = -1;
        goto end;
    }

    new_dict_entry_l = strlen(new_dict_entry) + 1;
    bundle->primary->dict = (char *) realloc(bundle->primary->dict, bundle->primary->dict_length + new_dict_entry_l);
    memcpy(bundle->primary->dict + bundle->primary->dict_length, new_dict_entry, new_dict_entry_l);

    entry_offset = bundle->primary->dict_length;
    bundle->primary->dict_length += new_dict_entry_l;

    ret = entry_offset;
end:
    return ret;
}

int bundle_set_primary_entry(bundle_s *bundle, primary_field_e field, const char *new_dict_entry)
{
    int entry_offset = 0, ret = 0;

    if (!bundle)
    {
        ret = 1;
        goto end;
    }

    entry_offset = bundle_get_dict_offset(bundle, field);

    // Already set. First we will remove the entry
    if (entry_offset > 0)
    {
        if ((ret = bundle_remove_dict_entry(bundle, entry_offset)) != 0)
            goto end;
    }

    // Add new entry
    entry_offset = bundle_add_dict_entry(bundle, new_dict_entry);
    if (entry_offset < 0)
    {
        ret = 1;
        goto end;
    }
    ret = bundle_set_dict_offset(bundle, field, entry_offset);

end:
    return ret;
}

int bundle_remove_primary_entry(bundle_s *bundle, primary_field_e field)
{
    int entry_offset = 0, ret = 0;

    if (!bundle)
    {
        ret = 1;
        goto end;
    }

    entry_offset = bundle_get_dict_offset(bundle, field);
    if (entry_offset > 0)
    {
        if ((ret = bundle_remove_dict_entry(bundle, entry_offset)) != 0)
            goto end;
    }

    ret = bundle_set_dict_offset(bundle, field, 0);

end:
    return ret;
}
/**/

/* Payload Block RFC5050 */
payload_block_s *bundle_new_payload_block()
{
    payload_block_s *payload_block = (payload_block_s *)calloc(1, sizeof(payload_block_s));
    payload_block->body.payload = (payload_body_s *)calloc(1, sizeof(payload_body_s));
    payload_block->type = PAYL_B;

    return payload_block;
}

int bundle_set_payload(payload_block_s *block, uint8_t *payload, int payload_l)
{
    int ret = 0;
    if (!block)
    {
        ret = 1;
        goto end;
    }
    if (block->body.payload->payload)
        free(block->body.payload->payload);

    block->body.payload->payload = (uint8_t *)malloc(sizeof(uint8_t) * payload_l);
    memcpy(block->body.payload->payload, payload, payload_l);

    block->length = payload_l;

end:
    return ret;
}
/**/

/* Metadata Extension Block RFC6258 */
meb_s *bundle_new_meb()
{
    meb_s *meb = (meb_s *)calloc(1, sizeof(meb_s));
    meb->type = META_B;
    meb->body.meb = (meb_body_s *)calloc(1, sizeof(meb_body_s));

    return meb;
}

int bundle_set_metadata(meb_s *block, uint64_t meta_type, uint8_t *metadata, int metadata_l)
{
    int ret = 0;
    if (!block)
    {
        ret = 1;
        goto end;
    }

    block->body.meb->type = meta_type;
    if (block->body.meb->metadata.metadata)
        free(block->body.meb->metadata.metadata);
    block->body.meb->metadata.metadata = (uint8_t *)malloc(sizeof(uint8_t) * metadata_l);
    memcpy(block->body.meb->metadata.metadata, metadata, metadata_l);

    // Maybe we could directly encode the metadata as required and put the correct length in the metadata block header. At the moment, this is easier.
    block->body.meb->metadata_l = metadata_l;

end:
    return ret;
}
/**/

int bundle_set_ext_block_flags(ext_block_s *ext_block, uint8_t flags)
{
    int ret = 0;

    if (!ext_block)
    {
        ret = 1;
        goto end;
    }

    ext_block->proc_flags |= flags;

end:
    return ret;

}

int bundle_add_ext_block(bundle_s *bundle, ext_block_s *ext_block)
{
    int ret = 0;
    ext_block_s **next = NULL;

    if (!bundle || !ext_block)
    {
        ret = 1;
        goto end;
    }

    next = &bundle->ext;
    while (*next)
    {
        next = &(*next)->next;
    }
    *next = (ext_block_s *)malloc(sizeof(ext_block_s));
    memcpy(*next, ext_block, sizeof(ext_block_s));
end:
    return ret;
}

/* Bundle status report functions*/
bundle_sr *bundle_sr_new()
{
    bundle_sr *sr = (bundle_sr *)calloc(1, sizeof(bundle_sr));

    return sr;
}

int bundle_sr_free(bundle_sr *sr)
{
    free(sr);

    return 0;
}

int bundle_sr_raw(bundle_sr *sr, /*out*/uint8_t **sr_raw)
{
    int sr_raw_l, off = 0;;

    // Calculate sr length
    sr_raw_l = sizeof(sr->status_flags) + sizeof(sr->reason_codes);
    if (sr->fragment_offset)
        sr_raw_l += sdnv_encoding_len(sr->fragment_offset);
    if (sr->fragment_length)
        sr_raw_l += sdnv_encoding_len(sr->fragment_length);
    if (sr->sec_time_of_receipt)
        sr_raw_l += sdnv_encoding_len(sr->sec_time_of_receipt);
    if (sr->usec_time_of_receipt)
        sr_raw_l += sdnv_encoding_len(sr->usec_time_of_receipt);
    if (sr->sec_time_of_qustody)
        sr_raw_l += sdnv_encoding_len(sr->sec_time_of_qustody);
    if (sr->usec_time_of_qustody)
        sr_raw_l += sdnv_encoding_len(sr->usec_time_of_qustody);
    if (sr->sec_time_of_forwarding)
        sr_raw_l += sdnv_encoding_len(sr->sec_time_of_forwarding);
    if (sr->usec_time_of_forwarding)
        sr_raw_l += sdnv_encoding_len(sr->usec_time_of_forwarding);
    if (sr->sec_time_of_delivery)
        sr_raw_l += sdnv_encoding_len(sr->sec_time_of_delivery);
    if (sr->usec_time_of_delivery)
        sr_raw_l += sdnv_encoding_len(sr->usec_time_of_delivery);
    if (sr->sec_time_of_deletion)
        sr_raw_l += sdnv_encoding_len(sr->sec_time_of_deletion);
    if (sr->usec_time_of_deletion)
        sr_raw_l += sdnv_encoding_len(sr->usec_time_of_deletion);
    sr_raw_l += sdnv_encoding_len(sr->cp_creation_timestamp);
    sr_raw_l += sdnv_encoding_len(sr->cp_creation_ts_seq_num);
    if (sr->source_EID_len)
    {
        sr_raw_l += sdnv_encoding_len(sr->source_EID_len);
        sr_raw_l += sr->source_EID_len;
    }

    *sr_raw = (uint8_t *)malloc(sr_raw_l);
    //Codify sr
    memcpy(*sr_raw, &sr->status_flags, sizeof(sr->status_flags));
    off++;
    memcpy(*sr_raw + off, &sr->reason_codes, sizeof(sr->reason_codes));
    off++;

    if (sr->fragment_offset)
        off += sdnv_encode(sr->fragment_offset, *sr_raw + off);
    if (sr->fragment_length)
        off += sdnv_encode(sr->fragment_length, *sr_raw + off);
    if (sr->sec_time_of_receipt)
        off += sdnv_encode(sr->sec_time_of_receipt, *sr_raw + off);
    if (sr->usec_time_of_receipt)
        off += sdnv_encode(sr->usec_time_of_receipt, *sr_raw + off);
    if (sr->sec_time_of_qustody)
        off += sdnv_encode(sr->sec_time_of_qustody, *sr_raw + off);
    if (sr->usec_time_of_qustody)
        off += sdnv_encode(sr->usec_time_of_qustody, *sr_raw + off);
    if (sr->sec_time_of_forwarding)
        off += sdnv_encode(sr->sec_time_of_forwarding, *sr_raw + off);
    if (sr->usec_time_of_forwarding)
        off += sdnv_encode(sr->usec_time_of_forwarding, *sr_raw + off);
    if (sr->sec_time_of_delivery)
        off += sdnv_encode(sr->sec_time_of_delivery, *sr_raw + off);
    if (sr->usec_time_of_delivery)
        off += sdnv_encode(sr->usec_time_of_delivery, *sr_raw + off);
    if (sr->sec_time_of_deletion)
        off += sdnv_encode(sr->sec_time_of_deletion, *sr_raw + off);
    if (sr->usec_time_of_deletion)
        off += sdnv_encode(sr->usec_time_of_deletion, *sr_raw + off);
    off += sdnv_encode(sr->cp_creation_timestamp, *sr_raw + off);
    off += sdnv_encode(sr->cp_creation_ts_seq_num, *sr_raw + off);

    if (sr->source_EID_len)
    {
        off += sdnv_encode(sr->source_EID_len, *sr_raw + off);
        memcpy(*sr_raw + off, sr->source_EID, sr->source_EID_len);
    }

    return sr_raw_l;
}
/**/


/* Bundle raw creation functions */
static int bundle_primary_raw(primary_block_s *primary_block, uint8_t **raw)
{
    int ret = 0, primary_block_l = 0, off = 0, max_raw_l = 0;
    size_t header_length = 0;

    // SDNV adds an overhead of 1:7 (one bit of overhead for each 7 bits of data to be encoded)
    primary_block_l = sizeof(*primary_block) + primary_block->dict_length;
    max_raw_l = ceil(primary_block_l * 8 / 7);
    *raw = (uint8_t *)malloc(max_raw_l);

    // Primary header length
    header_length += sdnv_encoding_len(primary_block->dest_scheme_offset);
    header_length += sdnv_encoding_len(primary_block->dest_ssp_offset);
    header_length += sdnv_encoding_len(primary_block->source_scheme_offset);
    header_length += sdnv_encoding_len(primary_block->source_ssp_offset);
    header_length += sdnv_encoding_len(primary_block->report_scheme_offset);
    header_length += sdnv_encoding_len(primary_block->report_ssp_offset);
    header_length += sdnv_encoding_len(primary_block->cust_scheme_offset);
    header_length += sdnv_encoding_len(primary_block->cust_ssp_offset);
    header_length += sdnv_encoding_len(primary_block->timestamp_time);
    header_length += sdnv_encoding_len(primary_block->timestamp_seq);
    header_length += sdnv_encoding_len(primary_block->lifetime);
    header_length += sdnv_encoding_len(primary_block->dict_length);
    header_length += primary_block->dict_length;
    if (primary_block->fragment_offset)
    {
        header_length += sdnv_encoding_len(primary_block->fragment_offset);
        header_length += sdnv_encoding_len(primary_block->total_length);
    }
    primary_block->length = header_length;

    // Encode bundle
    memcpy(*raw, &primary_block->version, sizeof(primary_block->version));
    off++;
    off += sdnv_encode(primary_block->proc_flags, *raw + off);
    off += sdnv_encode(primary_block->length, *raw + off);
    off += sdnv_encode(primary_block->dest_scheme_offset, *raw + off);
    off += sdnv_encode(primary_block->dest_ssp_offset, *raw + off);
    off += sdnv_encode(primary_block->source_scheme_offset, *raw + off);
    off += sdnv_encode(primary_block->source_ssp_offset, *raw + off);
    off += sdnv_encode(primary_block->report_scheme_offset, *raw + off);
    off += sdnv_encode(primary_block->report_ssp_offset, *raw + off);
    off += sdnv_encode(primary_block->cust_scheme_offset, *raw + off);
    off += sdnv_encode(primary_block->cust_ssp_offset, *raw + off);
    off += sdnv_encode(primary_block->timestamp_time, *raw + off);
    off += sdnv_encode(primary_block->timestamp_seq, *raw + off);
    off += sdnv_encode(primary_block->lifetime, *raw + off);
    off += sdnv_encode(primary_block->dict_length, *raw + off);
    memcpy(*raw + off, primary_block->dict, primary_block->dict_length);
    off += primary_block->dict_length;
    if (primary_block->fragment_offset)
    {
        off += sdnv_encoding_len(primary_block->fragment_offset);
        off += sdnv_encoding_len(primary_block->total_length);
    }

    ret = off;

    return ret;
}

// Length must be correctly set!!
static int bundle_ext_block_header_raw(ext_block_s *ext_block, uint8_t **raw)
{
    int ret = 0, max_raw_header_l = 0, off = 0;

    // Max header length considering SDNV encodings
    max_raw_header_l = 1 + ceil((1 + 1 + ext_block->EID_ref_count * 2 + 1) * 8 / 7);
    *raw = (uint8_t *)calloc(1, max_raw_header_l * sizeof(uint8_t));

    memcpy(*raw, &ext_block->type, sizeof(ext_block->type));
    off++;
    off += sdnv_encode(ext_block->proc_flags, *raw + off);

    // Only if 'block contains an EID-reference field' bit is set
    if ((ext_block->proc_flags & B_EID_RE) == B_EID_RE)
    {
        off += sdnv_encode(ext_block->EID_ref_count, *raw + off);
        if (ext_block->EID_ref_count > 0 && ext_block->eid_ref)
        {
            eid_ref_s *next_eid_ref = ext_block->eid_ref;
            do
            {
                off += sdnv_encode(next_eid_ref->scheme, *raw + off);
                off += sdnv_encode(next_eid_ref->ssp, *raw + off);
                next_eid_ref = next_eid_ref->next;
            }
            while (next_eid_ref == NULL);
        }
    }

    off += sdnv_encode(ext_block->length, *raw + off);
    ret = off;

    return ret;
}

// Extension body lenght is already the block->length (there aren't SDNV values)
static int bundle_payload_raw(payload_block_s *block, uint8_t **raw)
{
    int ret = 0, header_raw_l = 0, payload_raw_l = 0;

    // Create raw header
    header_raw_l = bundle_ext_block_header_raw((ext_block_s *)block, raw);

    // Total length
    payload_raw_l = header_raw_l + block->length;

    // Concatenate raw header and raw body.
    *raw = (uint8_t *) realloc(*raw, payload_raw_l);
    memcpy(*raw + header_raw_l, block->body.payload->payload, block->length);

    ret = payload_raw_l;

    return ret;
}


static int bundle_meb_raw(meb_s *block, uint8_t **raw)
{
    int ret = 0, header_raw_l = 0, meb_body_raw_l = 0, meb_raw_l = 0, off = 0;

    meb_body_raw_l = sdnv_encoding_len(block->body.meb->type) + block->body.meb->metadata_l;
    block->length = meb_body_raw_l;
    header_raw_l = bundle_ext_block_header_raw((ext_block_s *)block, raw);

    meb_raw_l = header_raw_l + meb_body_raw_l;

    *raw = (uint8_t *) realloc(*raw, meb_raw_l);
    off = header_raw_l;

    off += sdnv_encode(block->body.meb->type, *raw + off);
    memcpy(*raw + off, block->body.meb->metadata.metadata, block->body.meb->metadata_l);

    ret = meb_raw_l;

    return ret;
}

int bundle_create_raw(const bundle_s *bundle, /*out*/uint8_t **bundle_raw)
{
    int ret = -1, ext_raw_l = 0, bundle_raw_l = 0;
    uint8_t *ext_raw = NULL;
    ext_block_s *next_ext = NULL;

    // Header
    bundle_raw_l = bundle_primary_raw(bundle->primary, bundle_raw);
    if (!bundle->ext)
    {
        ret = bundle_raw_l;
        goto end;
    }

    // Extensions
    next_ext = bundle->ext;
    do
    {
        // Set last block flag
        if (next_ext->next == NULL)
            next_ext->proc_flags |= B_LAST;

        ext_raw_l = 0;
        switch (next_ext->type)
        {
        case PAYL_B:
            ext_raw_l = bundle_payload_raw((payload_block_s *) next_ext, &ext_raw);
            break;
        case META_B:
            ext_raw_l = bundle_meb_raw((meb_s *) next_ext, &ext_raw);
            break;
        }

        if (ext_raw_l != 0)
        {
            bundle_raw_l += ext_raw_l;
            *bundle_raw = (uint8_t *) realloc(*bundle_raw, bundle_raw_l);
            memcpy(*bundle_raw + (bundle_raw_l - ext_raw_l), ext_raw, ext_raw_l);
            free(ext_raw);
        }

        next_ext = next_ext->next;
    }
    while (next_ext);

    ret = bundle_raw_l;
end:
    return ret;
}

int bundle_free(bundle_s *b)
{
    int ret = 0;

    ext_block_s *next_ext = NULL, *old_ext = NULL;
    eid_ref_s *next_eid_ref = NULL, *old_eid_ref = NULL;

    if (b == NULL)
        goto end;

    if (b->primary != NULL)
    {
        if (b->primary->dict != NULL)
            free(b->primary->dict);
        free(b->primary);
    }

    next_ext = b->ext;
    while (next_ext != NULL)
    {
        switch (next_ext->type)
        {
        case PAYL_B:
            free(next_ext->body.payload->payload);
            next_ext->body.payload->payload = NULL;
            free(next_ext->body.payload);
            next_ext->body.payload = NULL;
            break;
        case META_B:
            free(next_ext->body.meb->metadata.metadata);
            next_ext->body.meb->metadata.metadata = NULL;
            next_eid_ref = next_ext->eid_ref;
            if (next_eid_ref != NULL)
            {
                old_eid_ref = next_eid_ref;
                next_eid_ref = next_eid_ref->next;
                free(old_eid_ref);
                old_eid_ref = NULL;
            }
            free(next_ext->body.meb);
            next_ext->body.meb = NULL;
            break;
        }
        old_ext = next_ext;
        next_ext = next_ext->next;
        free(old_ext);
        old_ext = NULL;
    }

    free(b);

end:
    return ret;
}

/**/

/* Bundle raw parsing functions */

//Returns the offset of the <field_num> SDNV field
int bundle_raw_get_sdnv_off(const uint8_t *raw, const int field_num)
{
    int i = 0, off = 0;

    for (i = 0; i < field_num; ++i)
    {
        off += sdnv_len(raw + off);
    }

    return off;
}

//Returns length of the ext block body
static inline int bundle_raw_get_body_off(const uint8_t *raw, /*out*/ int *ext_block_body_off)
{
    uint64_t EID_ref_count = 0, body_length = 0, proc_flags = 0;
    const uint8_t *b_pos = NULL;

    b_pos = raw;
    b_pos++; // Skip version / block type
    b_pos += sdnv_decode(b_pos, &proc_flags); // Decode proc_flags
    if (*raw != PRIM_B)   // If it is an ext. block
    {
        if (CHECK_BIT(proc_flags, 6))
        {
            b_pos += sdnv_decode(b_pos, &EID_ref_count); // Skip EID-ref-count
            if (EID_ref_count)
                b_pos += bundle_raw_get_sdnv_off(b_pos, EID_ref_count * 2); // Skip EID-refs
        }
    }
    b_pos += sdnv_decode(b_pos, &body_length); // Skip body length

    *ext_block_body_off = b_pos - raw;

    return body_length;
}


//Returns length of the ext block body
static inline int bundle_raw_ext_get_block_body(const uint8_t *bundle_raw, block_type_e block_type, /*out*/uint8_t **body)
{
    size_t body_l = 0;
    int ret = 0, block_off = 0, body_off = 0;

    // Find block
    if ((block_off = bundle_raw_find_block_off(bundle_raw, block_type)) < 0)
    {
        ret = -1;
        goto end;
    }

    // Get body length and offset
    body_l = bundle_raw_get_body_off(bundle_raw + block_off, &body_off);
    *body = (uint8_t *)malloc(body_l * sizeof(uint8_t));

    // Get body content
    memcpy(*body, bundle_raw + block_off + body_off, body_l);
    ret = body_l;
end:
    return ret;
}

// Returns offset to next block
int bundle_raw_next_block_off(const uint8_t *raw)
{
    int body_l = 0, body_off = 0;

    body_l = bundle_raw_get_body_off(raw, &body_off);
    return (body_l + body_off); // Skip to next block
}


int bundle_raw_get_proc_flags(const uint8_t *primary_raw, /*out*/uint64_t *flags)
{
    int off = 0, ret = 0;

    off++; //Skyp version
    if (sdnv_decode(primary_raw + off, flags) == 0)
        ret = 1;

    return ret;
}

int bundle_raw_set_proc_flags(uint8_t *primary_raw, /*out*/uint64_t new_flags)
{
    int off = 0, ret = 0, old_flags_l = 0, new_flags_l = 0;
    uint64_t old_flags = 0;

    off++;
    old_flags_l = sdnv_decode(primary_raw + off, &old_flags);
    new_flags_l = sdnv_encoding_len(new_flags);
    if (old_flags_l ==  new_flags_l)
    {
        sdnv_encode(new_flags, primary_raw + off);
    }
    else
    {
        ret = 1;
    }

    return ret;
}

int bundle_raw_ext_get_proc_flags(const uint8_t *ext_raw, /*out*/uint8_t *flags)
{
    uint64_t flags_32 = 0, ret = 0;

    ret = bundle_raw_get_proc_flags(ext_raw, &flags_32);
    *flags = flags_32;

    return ret;
}

int bundle_raw_ext_set_proc_flags(uint8_t *ext_raw, uint8_t new_flags)
{
    uint64_t flags_32 = 0;
    flags_32 = new_flags;

    return bundle_raw_set_proc_flags(ext_raw, flags_32);
}

//Returs 1 if current block is the last one 0 otherwise
int bundle_raw_ext_is_last_block(const uint8_t *raw)
{
    uint8_t block_flags = 0;
    int ret = 0;

    if (*raw != PRIM_B && bundle_raw_ext_get_proc_flags(raw, &block_flags) == 0)
    {
        if ((block_flags & B_LAST) == B_LAST)
            ret = 1;
    }

    return ret;
}

//Returns the offset start of the block with id <block_id>.
int bundle_raw_find_block_off(const uint8_t *raw, const uint8_t block_id)
{
    int next_block_off = 0;
    const uint8_t *b_pos = NULL;

    b_pos = raw;
    for (;;)
    {
        uint8_t actual_block_id = 0;
        //Check block type
        actual_block_id = *b_pos;
        if (actual_block_id == block_id)
        {
            next_block_off = b_pos - raw;
            break;
        }
        if (bundle_raw_ext_is_last_block(b_pos) == 1)
        {
            next_block_off = -1;
            break;
        }
        b_pos += bundle_raw_next_block_off(b_pos);
    }

    return next_block_off;
}


int bundle_raw_get_primary_field(const uint8_t *bundle_raw, const primary_field_e field_id, /*out*/char **field)
{
    int ret = 0, sdnv_field_off = 0, dict_off = 0;
    const uint8_t *b_pos = NULL;
    uint64_t field_off = 0;

    b_pos = bundle_raw;
    if (*b_pos != PRIM_B)
    {
        ret = 1;
        goto end;
    }
    b_pos++; // Skip Version

    sdnv_field_off = bundle_raw_get_sdnv_off(b_pos, 2 + field_id); // Skip proc_flags, block_length and fields before target field
    b_pos += sdnv_field_off;

    if (sdnv_len(b_pos) <= sizeof(field_off))
    {
        sdnv_decode(b_pos, &field_off);
    }
    else     // Something went wrong
    {
        ret = 1;
        goto end;
    }

    // Get string from dict
    dict_off = bundle_raw_get_sdnv_off(b_pos, 12 - field_id);
    b_pos += dict_off;
    *field = strdup((char *)(b_pos + field_off));

end:
    return ret;
}

int bunlde_raw_get_timestamp_and_seq(const uint8_t *bundle_raw, /*out*/uint64_t *timestamp_time, /*out*/uint64_t *timestamp_seq)
{
    unsigned off = 0;

    off++; // Skip version
    off += bundle_raw_get_sdnv_off(bundle_raw + off, 10); // Get timestamp_time offset
    off += sdnv_decode(bundle_raw + off, timestamp_time);
    off += sdnv_decode(bundle_raw + off, timestamp_seq);

    return 0;
}

int bundle_raw_get_lifetime(const uint8_t *bundle_raw, /*out*/uint64_t *lifetime)
{
    unsigned off = 0;

    off++; //Skip version
    off += bundle_raw_get_sdnv_off(bundle_raw + off, 12);
    off += sdnv_decode(bundle_raw + off, lifetime);

    return 0;
}

int bundle_raw_get_payload(const uint8_t *bundle_raw, /*out*/uint8_t **payload)
{
    return bundle_raw_ext_get_block_body(bundle_raw, PAYL_B, payload);
}

int bundle_raw_get_metadata(const uint8_t *bundle_raw, /*out*/uint64_t *metadata_type, /*out*/uint8_t **metadata)
{
    uint8_t *metadata_raw = NULL;
    size_t metadata_l = 0;

    metadata_l = bundle_raw_ext_get_block_body(bundle_raw, META_B, &metadata_raw);

    sdnv_decode(metadata_raw, metadata_type);
    *metadata = (uint8_t *)malloc((metadata_l - 1) * sizeof(uint8_t));
    memcpy(*metadata, metadata_raw + 1, metadata_l - 1);

    free(metadata_raw);

    return metadata_l - 1;
}