#include "sys/acpi.h"

#include <stddef.h>
#include <stdint.h>

#include "boot/boot_requests.h"
#include "arch/x86_64/paging.h"
#include "arch/x86_64/io.h"
#include "lib/log.h"
#include "sys/aml.h"

struct acpi_rsdp {
    char signature[8];
    uint8_t checksum;
    char oem_id[6];
    uint8_t revision;
    uint32_t rsdt_addr;
    uint32_t length;
    uint64_t xsdt_addr;
    uint8_t ext_checksum;
    uint8_t reserved[3];
} __attribute__((packed));

struct acpi_sdt_header {
    char signature[4];
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    char oem_id[6];
    char oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} __attribute__((packed));

struct acpi_fadt {
    struct acpi_sdt_header hdr;
    uint32_t firmware_ctrl;
    uint32_t dsdt;
    uint8_t reserved0;
    uint8_t preferred_pm_profile;
    uint16_t sci_int;
    uint32_t smi_cmd;
    uint8_t acpi_enable;
    uint8_t acpi_disable;
    uint8_t s4bios_req;
    uint8_t pstate_cnt;
    uint32_t pm1a_evt_blk;
    uint32_t pm1b_evt_blk;
    uint32_t pm1a_cnt_blk;
    uint32_t pm1b_cnt_blk;
    uint32_t pm2_cnt_blk;
    uint32_t pm_tmr_blk;
    uint32_t gpe0_blk;
    uint32_t gpe1_blk;
    uint8_t pm1_evt_len;
    uint8_t pm1_cnt_len;
    uint8_t pm2_cnt_len;
    uint8_t pm_tmr_len;
    uint8_t gpe0_blk_len;
    uint8_t gpe1_blk_len;
    uint8_t gpe1_base;
    uint8_t cst_cnt;
    uint16_t p_lvl2_lat;
    uint16_t p_lvl3_lat;
    uint16_t flush_size;
    uint16_t flush_stride;
    uint8_t duty_offset;
    uint8_t duty_width;
    uint8_t day_alrm;
    uint8_t mon_alrm;
    uint8_t century;
    uint16_t iapc_boot_arch;
    uint8_t reserved1;
    uint32_t flags;
    uint8_t reset_reg[12];
    uint8_t reset_value;
    uint8_t reserved2[3];
    uint64_t x_firmware_ctrl;
    uint64_t x_dsdt;
} __attribute__((packed));

enum {
    ACPI_MAX_PSTATES = 16
};

static int g_acpi_ready = 0;
static const struct acpi_sdt_header *g_dsdt_hdr = NULL;
static const uint8_t *g_dsdt_aml = NULL;
static uint32_t g_dsdt_aml_len = 0;
static int g_pss_count = -1;
static int g_pct_count = -1;
static struct acpi_pstate g_pstates[ACPI_MAX_PSTATES];
static uint32_t g_pstate_count = 0;
static struct acpi_gas g_pct_ctrl;
static struct acpi_gas g_pct_stat;
static int g_pct_valid = 0;
static const struct acpi_fadt *g_fadt = NULL;

#define ACPI_SLP_TYP_MASK 0x1C00u
#define ACPI_SLP_EN_BIT   0x2000u

static struct acpi_thermal_info g_thermal = {0};

enum {
    ACPI_AML_SCAN_LIMIT = 256 * 1024
};

static inline const void *acpi_map_phys(uint64_t phys) {
    return (const void *)(uintptr_t)(paging_hhdm_offset() + phys);
}

static int acpi_phys_in_memmap(uint64_t phys, uint64_t length) {
    if (!memmap_request.response) return 0;
    uint64_t end = phys + length;
    if (end < phys) return 0;
    struct limine_memmap_response *resp = memmap_request.response;
    for (uint64_t i = 0; i < resp->entry_count; ++i) {
        struct limine_memmap_entry *e = resp->entries[i];
        if (!e) continue;
        uint64_t e_end = e->base + e->length;
        if (phys >= e->base && end <= e_end) return 1;
    }
    return 0;
}

static int acpi_sig_eq(const char sig[4], const char *str) {
    return sig[0] == str[0] && sig[1] == str[1] && sig[2] == str[2] && sig[3] == str[3];
}

static int aml_read_pkg_length(const uint8_t *p, uint32_t *out_len, uint32_t *out_consumed) {
    if (!p || !out_len || !out_consumed) return 0;
    uint8_t lead = p[0];
    uint8_t byte_count = (uint8_t)((lead >> 6) & 0x3);
    uint32_t len = (uint32_t)(lead & 0x0F);
    for (uint8_t i = 0; i < byte_count; ++i) {
        len |= (uint32_t)p[1 + i] << (4 + 8 * i);
    }
    *out_len = len;
    *out_consumed = (uint32_t)(1 + byte_count);
    return 1;
}

static int aml_parse_nameseg(const uint8_t *p, char out[5]) {
    for (int i = 0; i < 4; ++i) {
        char c = (char)p[i];
        if (!c) return 0;
        out[i] = c;
    }
    out[4] = '\0';
    return 1;
}

static int aml_match_name(const uint8_t *p, const char *target, uint32_t *consumed) {
    if (!p || !target || !consumed) return 0;
    uint32_t off = 0;
    if (p[off] == '\\' || p[off] == '^') {
        off++;
    }
    if (p[off] == 0x2E) { /* DualNamePrefix */
        off++;
        char seg[5];
        if (!aml_parse_nameseg(&p[off], seg)) return 0;
        if (seg[0] == target[0] && seg[1] == target[1] &&
            seg[2] == target[2] && seg[3] == target[3]) {
            *consumed = off + 8;
            return 1;
        }
        *consumed = off + 8;
        return 0;
    }
    char seg[5];
    if (!aml_parse_nameseg(&p[off], seg)) return 0;
    *consumed = off + 4;
    return (seg[0] == target[0] && seg[1] == target[1] &&
            seg[2] == target[2] && seg[3] == target[3]);
}

static int aml_parse_package_count(const uint8_t *p, uint32_t *out_count) {
    if (!p || p[0] != 0x12 || !out_count) return 0;
    uint32_t pkg_len = 0;
    uint32_t consumed = 0;
    if (!aml_read_pkg_length(&p[1], &pkg_len, &consumed)) return 0;
    uint32_t idx = 1 + consumed;
    *out_count = p[idx];
    return 1;
}

static int aml_find_name_package(const uint8_t *aml, uint32_t len, const char *name, uint32_t *out_count) {
    for (uint32_t i = 0; i + 6 < len; ++i) {
        if (aml[i] != 0x08) continue; /* NameOp */
        uint32_t name_len = 0;
        if (!aml_match_name(&aml[i + 1], name, &name_len)) continue;
        uint32_t obj = i + 1 + name_len;
        if (obj < len && aml[obj] == 0x12) {
            uint32_t count = 0;
            if (aml_parse_package_count(&aml[obj], &count)) {
                *out_count = count;
                return 1;
            }
        }
    }
    return 0;
}

static int aml_locate_name_package(const uint8_t *aml, uint32_t len, const char *name,
                                   const uint8_t **out_pkg, uint32_t *out_pkg_len) {
    if (!aml || !out_pkg || !out_pkg_len) return 0;
    for (uint32_t i = 0; i + 6 < len; ++i) {
        if (aml[i] != 0x08) continue; /* NameOp */
        uint32_t name_len = 0;
        if (!aml_match_name(&aml[i + 1], name, &name_len)) continue;
        uint32_t obj = i + 1 + name_len;
        if (obj >= len || aml[obj] != 0x12) continue; /* PackageOp */
        uint32_t pkg_len = 0;
        uint32_t consumed = 0;
        if (!aml_read_pkg_length(&aml[obj + 1], &pkg_len, &consumed)) continue;
        *out_pkg = &aml[obj];
        *out_pkg_len = 1 + consumed + pkg_len;
        return 1;
    }
    return 0;
}

static int aml_parse_integer(const uint8_t *p, uint32_t len, uint64_t *out, uint32_t *consumed) {
    if (!p || !out || !consumed || len == 0) return 0;
    uint8_t op = p[0];
    if (op == 0x00) { *out = 0; *consumed = 1; return 1; }
    if (op == 0x01) { *out = 1; *consumed = 1; return 1; }
    if (op == 0xFF) { *out = 0xFFFFFFFFFFFFFFFFull; *consumed = 1; return 1; }
    if (op == 0x0A && len >= 2) { *out = p[1]; *consumed = 2; return 1; }
    if (op == 0x0B && len >= 3) { *out = (uint16_t)(p[1] | (p[2] << 8)); *consumed = 3; return 1; }
    if (op == 0x0C && len >= 5) {
        *out = (uint32_t)(p[1] | (p[2] << 8) | (p[3] << 16) | (p[4] << 24));
        *consumed = 5; return 1;
    }
    if (op == 0x0E && len >= 9) {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i) v |= (uint64_t)p[1 + i] << (8 * i);
        *out = v; *consumed = 9; return 1;
    }
    return 0;
}

static int aml_parse_buffer(const uint8_t *p, uint32_t len, const uint8_t **out_buf, uint32_t *out_len, uint32_t *consumed) {
    if (!p || !out_buf || !out_len || !consumed || len < 2) return 0;
    if (p[0] != 0x11) return 0; /* BufferOp */
    uint32_t pkg_len = 0;
    uint32_t pkg_consumed = 0;
    if (!aml_read_pkg_length(&p[1], &pkg_len, &pkg_consumed)) return 0;
    uint32_t idx = 1 + pkg_consumed;
    uint64_t buf_len = 0;
    uint32_t int_cons = 0;
    if (!aml_parse_integer(&p[idx], len - idx, &buf_len, &int_cons)) return 0;
    idx += int_cons;
    if (idx + buf_len > len) return 0;
    *out_buf = &p[idx];
    *out_len = (uint32_t)buf_len;
    *consumed = 1 + pkg_consumed + int_cons + (uint32_t)buf_len;
    return 1;
}

static int aml_parse_package_header(const uint8_t *p, uint32_t len, uint32_t *out_elements,
                                    uint32_t *out_hdr_consumed, uint32_t *out_total_len) {
    if (!p || len < 3 || p[0] != 0x12) return 0;
    uint32_t pkg_len = 0;
    uint32_t consumed = 0;
    if (!aml_read_pkg_length(&p[1], &pkg_len, &consumed)) return 0;
    uint32_t idx = 1 + consumed;
    if (idx >= len) return 0;
    *out_elements = p[idx];
    *out_hdr_consumed = idx + 1;
    *out_total_len = 1 + consumed + pkg_len;
    return 1;
}

static int aml_find_method_package(const uint8_t *aml, uint32_t len, const char *name, uint32_t *out_count);

static int aml_contains_nameseg(const uint8_t *aml, uint32_t len, const char seg[4]) {
    if (!aml || len < 4) return 0;
    for (uint32_t i = 0; i + 3 < len; ++i) {
        if (aml[i] == (uint8_t)seg[0] &&
            aml[i + 1] == (uint8_t)seg[1] &&
            aml[i + 2] == (uint8_t)seg[2] &&
            aml[i + 3] == (uint8_t)seg[3]) {
            return 1;
        }
    }
    return 0;
}

static int aml_has_name_or_method(const char *name) {
    if (!g_dsdt_aml || !g_dsdt_aml_len || !name) return 0;
    uint32_t count = 0;
    if (aml_find_name_package(g_dsdt_aml, g_dsdt_aml_len, name, &count)) return 1;
    if (aml_find_method_package(g_dsdt_aml, g_dsdt_aml_len, name, &count)) return 1;
    return 0;
}

static int aml_has_method_suffix(const char *suffix) {
    uint32_t len = 0;
    return aml_eval_method_return_suffix(suffix, &len) != NULL;
}

void acpi_thermal_init(void) {
    g_thermal.has_tz = 0;
    g_thermal.has_tmp = 0;
    g_thermal.has_crt = 0;
    g_thermal.has_psv = 0;
    g_thermal.has_hot = 0;
    g_thermal.has_tc1 = 0;
    g_thermal.has_tc2 = 0;
    g_thermal.has_tsp = 0;

    if (!g_acpi_ready || !g_dsdt_aml || !g_dsdt_aml_len) return;

    g_thermal.has_tz = aml_contains_nameseg(g_dsdt_aml, g_dsdt_aml_len, "_TZ_");
    g_thermal.has_tmp = aml_has_method_suffix("._TMP") || aml_has_name_or_method("_TMP");
    g_thermal.has_crt = aml_has_method_suffix("._CRT") || aml_has_name_or_method("_CRT");
    g_thermal.has_psv = aml_has_method_suffix("._PSV") || aml_has_name_or_method("_PSV");
    g_thermal.has_hot = aml_has_method_suffix("._HOT") || aml_has_name_or_method("_HOT");
    g_thermal.has_tc1 = aml_has_method_suffix("._TC1") || aml_has_name_or_method("_TC1");
    g_thermal.has_tc2 = aml_has_method_suffix("._TC2") || aml_has_name_or_method("_TC2");
    g_thermal.has_tsp = aml_has_method_suffix("._TSP") || aml_has_name_or_method("_TSP");
}

void acpi_thermal_log(void) {
    if (!g_acpi_ready) {
        log_printf("ACPI: thermal not ready\n");
        log_printf("ACPI: ready=%d fadt=%s dsdt_aml=%s len=%u\n",
                   g_acpi_ready,
                   g_fadt ? "yes" : "no",
                   g_dsdt_aml ? "yes" : "no",
                   (unsigned)g_dsdt_aml_len);
        if (!g_dsdt_aml || g_dsdt_aml_len == 0) return;
        acpi_thermal_init();
    }
    if (!g_thermal.has_tz) {
        log_printf("ACPI: _TZ_ not present (VMs often omit thermal zones)\n");
        return;
    }
    log_printf("ACPI: thermal zones present\n");
    log_printf("ACPI: _TMP=%s _CRT=%s _PSV=%s _HOT=%s _TC1=%s _TC2=%s _TSP=%s\n",
               g_thermal.has_tmp ? "yes" : "no",
               g_thermal.has_crt ? "yes" : "no",
               g_thermal.has_psv ? "yes" : "no",
               g_thermal.has_hot ? "yes" : "no",
               g_thermal.has_tc1 ? "yes" : "no",
               g_thermal.has_tc2 ? "yes" : "no",
               g_thermal.has_tsp ? "yes" : "no");
}

const struct acpi_thermal_info *acpi_thermal_info(void) {
    return &g_thermal;
}
// Man fuck this shid - Void
static int acpi_parse_sleep_pkg(const uint8_t *pkg, uint32_t pkg_len,
                                struct acpi_sleep_state *out) {
    if (!pkg || !out) return 0;
    uint32_t elements = 0, hdr = 0, total = 0;
    if (!aml_parse_package_header(pkg, pkg_len, &elements, &hdr, &total)) return 0;
    if (elements < 2) return 0;
    uint32_t idx = hdr;
    uint64_t vals[2] = {0, 0};
    for (uint32_t i = 0; i < 2; ++i) {
        uint32_t cons = 0;
        if (!aml_parse_integer(&pkg[idx], pkg_len - idx, &vals[i], &cons)) return 0;
        idx += cons;
    }
    out->typ_a = (uint16_t)vals[0];
    out->typ_b = (uint16_t)vals[1];
    return 1;
}

static const uint8_t *acpi_find_sleep_pkg(const char *name, uint32_t *pkg_len, int *via_method) {
    if (!name || !pkg_len) return NULL;
    const uint8_t *pkg = NULL;
    if (aml_locate_name_package(g_dsdt_aml, g_dsdt_aml_len, name, &pkg, pkg_len)) {
        if (via_method) *via_method = 0;
        return pkg;
    }
    if (via_method) *via_method = 1;
    if (name) {
        char path[20] = {0};
        /* Try CPU0 scope first */
        path[0] = '\\';
        path[1] = '_';
        path[2] = 'P';
        path[3] = 'R';
        path[4] = '.';
        path[5] = 'C';
        path[6] = 'P';
        path[7] = 'U';
        path[8] = '0';
        path[9] = '.';
        int idx = 10;
        for (int i = 0; i < 4 && name[i]; ++i) path[idx++] = name[i];
        path[idx] = '\0';
        pkg = aml_eval_method_return(path, pkg_len);
        if (!pkg) {
            path[0] = '\\';
            idx = 1;
            for (int i = 0; i < 4 && name[i]; ++i) path[idx++] = name[i];
            path[idx] = '\0';
            pkg = aml_eval_method_return(path, pkg_len);
        }
    }
    if (!pkg) {
        char suffix[6] = {0};
        if (name && name[0] == '_' && name[1] && name[2]) {
            suffix[0] = '.';
            suffix[1] = name[0];
            suffix[2] = name[1];
            suffix[3] = name[2];
            suffix[4] = name[3];
            suffix[5] = '\0';
            pkg = aml_eval_method_return_suffix(suffix, pkg_len);
        } else {
            pkg = aml_eval_method_return_suffix(name, pkg_len);
        }
    }
    return pkg;
}

static int acpi_get_sleep_pkg(const char *name, struct acpi_sleep_state *out) {
    uint32_t pkg_len = 0;
    int via_method = 0;
    const uint8_t *pkg = acpi_find_sleep_pkg(name, &pkg_len, &via_method);
    if (!pkg) return 0;
    log_printf("ACPI: %s via %s\n", name, via_method ? "Method" : "Name");
    return acpi_parse_sleep_pkg(pkg, pkg_len, out);
}

static void acpi_parse_pss(void) {
    g_pstate_count = 0;
    const uint8_t *pkg = NULL;
    uint32_t pkg_len = 0;
    if (!aml_locate_name_package(g_dsdt_aml, g_dsdt_aml_len, "_PSS", &pkg, &pkg_len)) {
        pkg = aml_eval_method_return("\\_PR.CPU0._PSS", &pkg_len);
        if (!pkg) pkg = aml_eval_method_return("\\_PSS", &pkg_len);
        if (!pkg) pkg = aml_eval_method_return_suffix("._PSS", &pkg_len);
        if (!pkg) return;
        log_printf("ACPI: _PSS via Method\n");
    } else {
        log_printf("ACPI: _PSS via Name\n");
    }
    uint32_t elements = 0, hdr = 0, total = 0;
    if (!aml_parse_package_header(pkg, pkg_len, &elements, &hdr, &total)) return;
    uint32_t idx = hdr;
    for (uint32_t e = 0; e < elements && g_pstate_count < ACPI_MAX_PSTATES; ++e) {
        if (idx >= pkg_len) break;
        if (pkg[idx] != 0x12) break;
        uint32_t sub_elems = 0, sub_hdr = 0, sub_total = 0;
        if (!aml_parse_package_header(&pkg[idx], pkg_len - idx, &sub_elems, &sub_hdr, &sub_total)) break;
        uint32_t sub_idx = idx + sub_hdr;
        uint64_t vals[6] = {0};
        for (uint32_t i = 0; i < 6 && i < sub_elems; ++i) {
            uint32_t cons = 0;
            if (!aml_parse_integer(&pkg[sub_idx], pkg_len - sub_idx, &vals[i], &cons)) break;
            sub_idx += cons;
        }
        struct acpi_pstate *ps = &g_pstates[g_pstate_count++];
        ps->freq_mhz = (uint32_t)vals[0];
        ps->power_mw = (uint32_t)vals[1];
        ps->trans_lat = (uint32_t)vals[2];
        ps->bus_lat = (uint32_t)vals[3];
        ps->control = (uint32_t)vals[4];
        ps->status = (uint32_t)vals[5];
        idx += sub_total;
    }
}

static void acpi_parse_pct(void) {
    g_pct_valid = 0;
    const uint8_t *pkg = NULL;
    uint32_t pkg_len = 0;
    if (!aml_locate_name_package(g_dsdt_aml, g_dsdt_aml_len, "_PCT", &pkg, &pkg_len)) {
        pkg = aml_eval_method_return("\\_PR.CPU0._PCT", &pkg_len);
        if (!pkg) pkg = aml_eval_method_return("\\_PCT", &pkg_len);
        if (!pkg) pkg = aml_eval_method_return_suffix("._PCT", &pkg_len);
        if (!pkg) return;
        log_printf("ACPI: _PCT via Method\n");
    } else {
        log_printf("ACPI: _PCT via Name\n");
    }
    uint32_t elements = 0, hdr = 0, total = 0;
    if (!aml_parse_package_header(pkg, pkg_len, &elements, &hdr, &total)) return;
    uint32_t idx = hdr;
    struct acpi_gas *gases[2] = { &g_pct_ctrl, &g_pct_stat };
    for (uint32_t e = 0; e < elements && e < 2; ++e) {
        if (idx >= pkg_len) return;
        if (pkg[idx] == 0x11) {
            const uint8_t *buf = NULL;
            uint32_t blen = 0, cons = 0;
            if (!aml_parse_buffer(&pkg[idx], pkg_len - idx, &buf, &blen, &cons)) return;
            if (blen < sizeof(struct acpi_gas)) return;
            const struct acpi_gas *src = (const struct acpi_gas *)buf;
            *gases[e] = *src;
            idx += cons;
        } else if (pkg[idx] == 0x12) {
            uint32_t sub_elems = 0, sub_hdr = 0, sub_total = 0;
            if (!aml_parse_package_header(&pkg[idx], pkg_len - idx, &sub_elems, &sub_hdr, &sub_total)) return;
            uint32_t sub_idx = idx + sub_hdr;
            const uint8_t *buf = NULL;
            uint32_t blen = 0, cons = 0;
            if (!aml_parse_buffer(&pkg[sub_idx], pkg_len - sub_idx, &buf, &blen, &cons)) return;
            if (blen < sizeof(struct acpi_gas)) return;
            const struct acpi_gas *src = (const struct acpi_gas *)buf;
            *gases[e] = *src;
            idx += sub_total;
        } else {
            return;
        }
    }
    g_pct_valid = 1;
}

static int aml_find_method_package(const uint8_t *aml, uint32_t len, const char *name, uint32_t *out_count) {
    for (uint32_t i = 0; i + 8 < len; ++i) {
        if (aml[i] != 0x14) continue; /* MethodOp */
        uint32_t pkg_len = 0;
        uint32_t pkg_consumed = 0;
        if (!aml_read_pkg_length(&aml[i + 1], &pkg_len, &pkg_consumed)) continue;
        uint32_t name_len = 0;
        if (!aml_match_name(&aml[i + 1 + pkg_consumed], name, &name_len)) continue;
        uint32_t body = i + 1 + pkg_consumed + name_len + 1; /* +flags */
        if (body >= len) continue;
        uint32_t body_len = pkg_len - (pkg_consumed + name_len + 1);
        uint32_t end = body + body_len;
        if (end > len) end = len;
        for (uint32_t j = body; j + 2 < end; ++j) {
            if (aml[j] == 0xA4) { /* ReturnOp */
                if (aml[j + 1] == 0x12) {
                    uint32_t count = 0;
                    if (aml_parse_package_count(&aml[j + 1], &count)) {
                        *out_count = count;
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

static void acpi_find_pss_pct(void) {
    g_pss_count = -1;
    g_pct_count = -1;
    if (!g_dsdt_aml || g_dsdt_aml_len == 0) return;
    if (g_dsdt_aml_len > ACPI_AML_SCAN_LIMIT) {
        log_printf("ACPI: AML length %u too large, skipping AML scan\n",
                   (unsigned)g_dsdt_aml_len);
        return;
    }

    uint32_t count = 0;
    if (aml_find_name_package(g_dsdt_aml, g_dsdt_aml_len, "_PSS", &count) ||
        aml_find_method_package(g_dsdt_aml, g_dsdt_aml_len, "_PSS", &count)) {
        g_pss_count = (int)count;
    }
    count = 0;
    if (aml_find_name_package(g_dsdt_aml, g_dsdt_aml_len, "_PCT", &count) ||
        aml_find_method_package(g_dsdt_aml, g_dsdt_aml_len, "_PCT", &count)) {
        g_pct_count = (int)count;
    }
}

void acpi_init(void) {
    g_acpi_ready = 0;
    g_dsdt_hdr = NULL;
    g_dsdt_aml = NULL;
    g_dsdt_aml_len = 0;
    g_pss_count = -1;
    g_pct_count = -1;
    g_pstate_count = 0;
    g_pct_valid = 0;

    if (!rsdp_request.response || !rsdp_request.response->address) {
        log_printf("ACPI: no RSDP\n");
        return;
    }

    /* Limine provides a mapped pointer for RSDP when LIMINE_NO_POINTERS is not set. */
    const struct acpi_rsdp *rsdp = (const struct acpi_rsdp *)rsdp_request.response->address;
    if (!rsdp || rsdp->signature[0] != 'R') {
        log_printf("ACPI: invalid RSDP\n");
        return;
    }

    uint64_t sdt_phys = 0;
    if (rsdp->revision >= 2 && rsdp->xsdt_addr) {
        sdt_phys = rsdp->xsdt_addr;
    } else {
        sdt_phys = rsdp->rsdt_addr;
    }

    if (!sdt_phys) {
        log_printf("ACPI: no RSDT/XSDT\n");
        return;
    }

    if (!acpi_phys_in_memmap(sdt_phys, sizeof(struct acpi_sdt_header))) {
        log_printf("ACPI: SDT not in memmap\n");
        return;
    }
    const struct acpi_sdt_header *sdt = (const struct acpi_sdt_header *)acpi_map_phys(sdt_phys);
    if (!sdt) {
        log_printf("ACPI: invalid SDT\n");
        return;
    }
    if (sdt->length < sizeof(*sdt) || sdt->length > 1024 * 1024) {
        log_printf("ACPI: SDT length invalid (%u)\n", (unsigned)sdt->length);
        return;
    }

    uint32_t entries = (sdt->length - sizeof(*sdt)) / ((rsdp->revision >= 2 && rsdp->xsdt_addr) ? 8 : 4);
    if (entries > 512) {
        log_printf("ACPI: SDT entries too large (%u), aborting\n", (unsigned)entries);
        return;
    }
    const uint8_t *entry_ptr = (const uint8_t *)sdt + sizeof(*sdt);
    const struct acpi_fadt *fadt = NULL;
    for (uint32_t i = 0; i < entries; ++i) {
        uint64_t tbl_phys = (rsdp->revision >= 2 && rsdp->xsdt_addr)
                                ? ((const uint64_t *)entry_ptr)[i]
                                : (uint64_t)((const uint32_t *)entry_ptr)[i];
        if (!tbl_phys) continue;
        if (!acpi_phys_in_memmap(tbl_phys, sizeof(struct acpi_sdt_header))) continue;
        const struct acpi_sdt_header *hdr = (const struct acpi_sdt_header *)acpi_map_phys(tbl_phys);
        if (hdr && acpi_sig_eq(hdr->signature, "FACP")) {
            fadt = (const struct acpi_fadt *)hdr;
            break;
        }
    }

    if (!fadt) {
        log_printf("ACPI: FADT not found\n");
        return;
    }
    g_fadt = fadt;

    uint64_t dsdt_phys = fadt->x_dsdt ? fadt->x_dsdt : (uint64_t)fadt->dsdt;
    if (!dsdt_phys) {
        log_printf("ACPI: DSDT missing\n");
        return;
    }

    if (!acpi_phys_in_memmap(dsdt_phys, sizeof(struct acpi_sdt_header))) {
        log_printf("ACPI: DSDT not in memmap\n");
        return;
    }
    g_dsdt_hdr = (const struct acpi_sdt_header *)acpi_map_phys(dsdt_phys);
    if (!g_dsdt_hdr || !acpi_sig_eq(g_dsdt_hdr->signature, "DSDT")) {
        log_printf("ACPI: invalid DSDT\n");
        return;
    }
    if (g_dsdt_hdr->length < sizeof(*g_dsdt_hdr) || g_dsdt_hdr->length > 1024 * 1024) {
        log_printf("ACPI: DSDT length invalid (%u)\n", (unsigned)g_dsdt_hdr->length);
        return;
    }

    g_dsdt_aml = (const uint8_t *)g_dsdt_hdr + sizeof(*g_dsdt_hdr);
    g_dsdt_aml_len = g_dsdt_hdr->length - sizeof(*g_dsdt_hdr);

    aml_init(g_dsdt_aml, g_dsdt_aml_len);
    acpi_find_pss_pct();
    acpi_parse_pss();
    acpi_parse_pct();
    acpi_thermal_init();
    g_acpi_ready = 1;
}

void acpi_log_status(void) {
    if (!g_acpi_ready) {
        log_printf("ACPI: not ready\n");
        return;
    }
    log_printf("ACPI: DSDT AML=%u bytes\n", (unsigned)g_dsdt_aml_len);
    if (g_pss_count >= 0) {
        log_printf("ACPI: _PSS package entries=%u parsed=%u\n",
                   (unsigned)g_pss_count, (unsigned)g_pstate_count);
    } else {
        log_printf("ACPI: _PSS not found\n");
    }
    if (g_pct_count >= 0) {
        log_printf("ACPI: _PCT package entries=%u parsed=%s\n",
                   (unsigned)g_pct_count, g_pct_valid ? "yes" : "no");
    } else {
        log_printf("ACPI: _PCT not found\n");
    }
}

int acpi_pss_count(void) {
    return g_pss_count;
}

int acpi_pct_count(void) {
    return g_pct_count;
}

const struct acpi_pstate *acpi_pss_table(uint32_t *count) {
    if (count) *count = g_pstate_count;
    return g_pstates;
}

int acpi_get_pct(struct acpi_gas *ctrl, struct acpi_gas *stat) {
    if (!g_pct_valid) return 0;
    if (ctrl) *ctrl = g_pct_ctrl;
    if (stat) *stat = g_pct_stat;
    return 1;
}

int acpi_get_sleep_state(uint8_t state, struct acpi_sleep_state *out) {
    if (!g_acpi_ready || !out) return 0;
    if (state == 3) return acpi_get_sleep_pkg("_S3", out);
    if (state == 4) return acpi_get_sleep_pkg("_S4", out);
    if (state == 5) return acpi_get_sleep_pkg("_S5", out);
    return 0;
}

static void acpi_enable_sci(void) {
    if (!g_fadt) return;
    if (g_fadt->smi_cmd && g_fadt->acpi_enable) {
        outb((uint16_t)g_fadt->smi_cmd, g_fadt->acpi_enable);
    }
}

int acpi_sleep(uint8_t state) {
    if (!g_fadt) return 0;
    if (!g_fadt->pm1a_cnt_blk) return 0;
    struct acpi_sleep_state ss;
    if (!acpi_get_sleep_state(state, &ss)) return 0;

    acpi_enable_sci();

    uint16_t pm1a = inw((uint16_t)g_fadt->pm1a_cnt_blk);
    pm1a &= ~ACPI_SLP_TYP_MASK;
    pm1a |= (uint16_t)((ss.typ_a & 0x7u) << 10);
    outw((uint16_t)g_fadt->pm1a_cnt_blk, pm1a);
    outw((uint16_t)g_fadt->pm1a_cnt_blk, (uint16_t)(pm1a | ACPI_SLP_EN_BIT));

    if (g_fadt->pm1b_cnt_blk) {
        uint16_t pm1b = inw((uint16_t)g_fadt->pm1b_cnt_blk);
        pm1b &= ~ACPI_SLP_TYP_MASK;
        pm1b |= (uint16_t)((ss.typ_b & 0x7u) << 10);
        outw((uint16_t)g_fadt->pm1b_cnt_blk, pm1b);
        outw((uint16_t)g_fadt->pm1b_cnt_blk, (uint16_t)(pm1b | ACPI_SLP_EN_BIT));
    }

    return 1;
}
