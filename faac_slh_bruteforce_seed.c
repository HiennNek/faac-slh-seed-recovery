// FAAC SLH seed brute-force - CPU (OpenMP)
// For 1-2 frames: finds ALL candidate seeds, shows top 50, saves full report
// For 3+ frames: fast path, stops at first match (unique result)
// Compile: gcc -O3 -fopenmp -lm -o faac_bf faac_slh_bruteforce_seed.c
// Run:     ./faac_bf <mfkey_hex> <data1_hex> [data2_hex ... dataN_hex]

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>

#define KEELOQ_NLF 0x3A5C742E
#define MAX_FRAMES 16
#define LIST_LIMIT 10000
#define TOP_SHOW 50

#define bit(x, n) (((x) >> (n)) & 1)

typedef struct {
    uint32_t seed;
    uint32_t dec[MAX_FRAMES];
    int gap;
    float pct;
} CandSort;

static int cmp_by_gap(const void *a, const void *b) {
    const CandSort *ca = (const CandSort*)a, *cb = (const CandSort*)b;
    return (ca->gap > cb->gap) - (ca->gap < cb->gap);
}

static int cmp_by_seed(const void *a, const void *b) {
    const CandSort *ca = (const CandSort*)a, *cb = (const CandSort*)b;
    return (ca->seed > cb->seed) - (ca->seed < cb->seed);
}

static inline uint8_t g5(uint32_t x, uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e) {
    return bit(x, a) | (bit(x, b) << 1) | (bit(x, c) << 2) | (bit(x, d) << 3) | (bit(x, e) << 4);
}

static inline uint32_t keeloq_encrypt(uint32_t data, uint64_t key) {
    uint32_t x = data;
    for (int r = 0; r < 528; r++)
        x = (x >> 1) | ((bit(x, 0) ^ bit(x, 16) ^ bit(key, r & 63) ^ bit(KEELOQ_NLF, g5(x, 1, 9, 20, 26, 31))) << 31);
    return x;
}

static inline uint32_t keeloq_decrypt(uint32_t data, uint64_t key) {
    uint32_t x = data;
    for (int r = 0; r < 528; r++)
        x = (x << 1) | (bit(x, 31) ^ bit(x, 15) ^ bit(key, (15 - r) & 63) ^ bit(KEELOQ_NLF, g5(x, 0, 8, 19, 25, 30)));
    return x;
}

static inline uint64_t faac_learning(uint32_t seed, uint64_t mfkey) {
    uint16_t hs = seed >> 16;
    uint32_t lsb = ((uint32_t)hs << 16) | 0x544D;
    return ((uint64_t)keeloq_encrypt(seed, mfkey) << 32) | keeloq_encrypt(lsb, mfkey);
}

static inline int validate(uint32_t decrypt, uint32_t code_fix) {
    uint8_t n[8];
    for (int i = 7; i >= 0; i--)
        n[7 - i] = (code_fix >> (i * 4)) & 0xF;
    uint32_t top = decrypt >> 20;
    uint32_t even = (n[6] << 8) | (n[7] << 4) | n[5];
    uint32_t odd  = (n[2] << 8) | (n[3] << 4) | n[4];
    return (top == even || top == odd);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <mfkey_hex> <data1_hex> [data2_hex ... dataN_hex]\n", argv[0]);
        return 1;
    }

    uint64_t mfkey = strtoull(argv[1], NULL, 16);
    int nf = argc - 2;
    if (nf > MAX_FRAMES) nf = MAX_FRAMES;

    uint32_t fix[MAX_FRAMES], hop[MAX_FRAMES];
    for (int i = 0; i < nf; i++) {
        uint64_t d = strtoull(argv[2 + i], NULL, 16);
        fix[i] = d >> 32;
        hop[i] = d & 0xFFFFFFFF;
        printf("Frame %d: Fix=0x%08X Hop=0x%08X Sn=%07lX Btn=%X\n",
               i + 1, fix[i], hop[i], (long)(fix[i] >> 4), fix[i] & 0xF);
    }

    // Generate report filename
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char fname[64];
    strftime(fname, sizeof(fname), "FAACBF_REPORT_%Y%m%d_%H%M%S.txt", tm);

    int use_fast = (nf >= 3);
    int same_btn = (nf > 1 && (fix[0] & 0xF) == (fix[1] & 0xF));

    if (use_fast) {
        printf("3+ frames -- unique seed expected, fast path.\n");
        volatile int found = 0;
        uint32_t found_seed = 0;
        uint64_t found_man = 0;

        #pragma omp parallel for
        for (uint64_t s = 0; s < (1ULL << 32); s++) {
            if (found) continue;
            uint32_t seed = (uint32_t)s;
            uint64_t man = faac_learning(seed, mfkey);
            int ok = 1;
            for (int i = 0; i < nf; i++) {
                uint32_t dec = keeloq_decrypt(hop[i], man);
                if (!validate(dec, fix[i])) { ok = 0; break; }
            }
            if (ok) {
                #pragma omp critical
                if (!found) {
                    found = 1;
                    found_seed = seed;
                    found_man = man;
                }
            }
        }

        FILE *fp = fopen(fname, "w");
        fprintf(fp, "FAAC SLH Seed Brute-Force Report\n");
        fprintf(fp, "MFKey: 0x%016lX\n", mfkey);
        fprintf(fp, "Frames: %d\n", nf);
        for (int i = 0; i < nf; i++)
            fprintf(fp, "  Frame %d: Fix=0x%08X Hop=0x%08X\n", i + 1, fix[i], hop[i]);
        fprintf(fp, "Search mode: fast path (3+ frames)\n");

        if (found) {
            fprintf(fp, "\n*** SEED = 0x%08X (100%% confidence, unique) ***\n", found_seed);
            for (int i = 0; i < nf; i++) {
                uint32_t dec = keeloq_decrypt(hop[i], found_man);
                fprintf(fp, "  Frame %d: decrypt=0x%08X cnt=%05X\n", i + 1, dec, dec & 0xFFFFF);
            }
            printf("\n*** SEED = 0x%08X *** (100%% confidence)\n", found_seed);
            printf("  Full report: %s\n", fname);
            for (int i = 0; i < nf; i++) {
                uint32_t dec = keeloq_decrypt(hop[i], found_man);
                printf("  Frame %d: decrypt=0x%08X cnt=%05X\n", i + 1, dec, dec & 0xFFFFF);
            }
        } else {
            fprintf(fp, "\nNot found.\n");
            printf("\nNot found. Wrong mfkey or protocol?\n");
        }
        fclose(fp);
    } else {
        printf("1-2 frames -- collecting all candidate seeds.\n");
        printf("  %d distinct button%s\n",
               same_btn ? 1 : (nf > 1 ? 2 : 1),
               same_btn ? "" : "s");

        uint32_t candidates[LIST_LIMIT];
        int count = 0;

        #pragma omp parallel for
        for (uint64_t s = 0; s < (1ULL << 32); s++) {
            uint32_t seed = (uint32_t)s;
            uint64_t man = faac_learning(seed, mfkey);
            int ok = 1;
            for (int i = 0; i < nf; i++) {
                uint32_t dec = keeloq_decrypt(hop[i], man);
                if (!validate(dec, fix[i])) { ok = 0; break; }
            }
            if (ok) {
                #pragma omp critical
                {
                    if (count < LIST_LIMIT)
                        candidates[count] = seed;
                    count++;
                }
            }
        }

        printf("\nFound %d candidates\n", count);

        FILE *fp = fopen(fname, "w");
        fprintf(fp, "FAAC SLH Seed Brute-Force Report\n");
        fprintf(fp, "MFKey: 0x%016lX\n", mfkey);
        fprintf(fp, "Frames: %d\n", nf);
        for (int i = 0; i < nf; i++)
            fprintf(fp, "  Frame %d: Fix=0x%08X Hop=0x%08X\n", i + 1, fix[i], hop[i]);
        fprintf(fp, "Search mode: collect (1-2 frames)\n");

        if (count == 0) {
            fprintf(fp, "\nNo candidates found.\n");
            printf("No candidates found. Wrong mfkey or protocol?\n");
            fclose(fp);
        } else {
            float eff_bits = 32.0f - log2f((float)count);
            fprintf(fp, "\nTotal candidates: %d\n", count);
            fprintf(fp, "Effective bits determined: %.1f / 32\n", eff_bits);

            int total = (count < LIST_LIMIT) ? count : 0;
            if (total > 0) {
                CandSort *cands = (CandSort*)malloc(total * sizeof(CandSort));
                for (int i = 0; i < total; i++) {
                    cands[i].seed = candidates[i];
                    uint64_t man = faac_learning(candidates[i], mfkey);
                    for (int j = 0; j < nf; j++)
                        cands[i].dec[j] = keeloq_decrypt(hop[j], man);
                    if (same_btn && nf == 2)
                        cands[i].gap = abs((int)(cands[i].dec[0] & 0xFFFFF) - (int)(cands[i].dec[1] & 0xFFFFF));
                    else
                        cands[i].gap = -1;
                }

                int sort_by_gap = (same_btn && nf == 2);
                if (sort_by_gap) {
                    qsort(cands, total, sizeof(CandSort), cmp_by_gap);
                    float total_score = 0;
                    for (int i = 0; i < total; i++)
                        total_score += 1.0f / (1.0f + cands[i].gap / 10.0f);
                    for (int i = 0; i < total; i++)
                        cands[i].pct = 100.0f / (1.0f + cands[i].gap / 10.0f) / total_score;

                    fprintf(fp, "Sorted by counter gap (smaller = more likely):\n\n");
                    for (int i = 0; i < total; i++) {
                        fprintf(fp, "%4d: SEED=0x%08X gap=%d (%.4f%%)\n", i + 1, cands[i].seed, cands[i].gap, cands[i].pct);
                        for (int j = 0; j < nf; j++)
                            fprintf(fp, "     Frame %d (btn=%X): decrypt=0x%08X cnt=%05X\n",
                                    j + 1, fix[j] & 0xF, cands[i].dec[j], cands[i].dec[j] & 0xFFFFF);
                    }

                    int show = total < TOP_SHOW ? total : TOP_SHOW;
                    printf("\n  Top %d / %d candidates (sorted by gap):\n", show, count);
                    printf("  Full report: %s\n", fname);
                    printf("----------------------------------------------------------\n");
                    for (int i = 0; i < show; i++) {
                        printf("%4d: SEED=0x%08X gap=%d (%.2f%%)\n", i + 1, cands[i].seed, cands[i].gap, cands[i].pct);
                        for (int j = 0; j < nf; j++) {
                            uint32_t dec_cnt = cands[i].dec[j] & 0xFFFFF;
                            const char *par = (dec_cnt & 1) ? "odd" : "even";
                            printf("     Frame %d (btn=%X): decrypt=0x%08X cnt=%05X (%s)\n",
                                   j + 1, fix[j] & 0xF, cands[i].dec[j], dec_cnt, par);
                        }
                    }
                    if (count > TOP_SHOW)
                        printf("  ... and %d more in report\n", count - TOP_SHOW);
                    printf("----------------------------------------------------------\n");
                } else {
                    qsort(cands, total, sizeof(CandSort), cmp_by_seed);
                    for (int i = 0; i < total; i++)
                        cands[i].pct = 100.0f / count;

                    fprintf(fp, "All %d candidates (sorted by seed, each = %.4f%%):\n\n", count, 100.0 / count);
                    for (int i = 0; i < total; i++) {
                        fprintf(fp, "%4d: SEED=0x%08X\n", i + 1, cands[i].seed);
                        for (int j = 0; j < nf; j++)
                            fprintf(fp, "     Frame %d (btn=%X): decrypt=0x%08X cnt=%05X\n",
                                    j + 1, fix[j] & 0xF, cands[i].dec[j], cands[i].dec[j] & 0xFFFFF);
                    }

                    int show = total < TOP_SHOW ? total : TOP_SHOW;
                    printf("\n  Top %d / %d candidates (sorted by seed):\n", show, count);
                    printf("  Full report: %s\n", fname);
                    printf("----------------------------------------------------------\n");
                    for (int i = 0; i < show; i++) {
                        printf("%4d: SEED=0x%08X\n", i + 1, cands[i].seed);
                        for (int j = 0; j < nf; j++) {
                            uint32_t dec_cnt = cands[i].dec[j] & 0xFFFFF;
                            const char *par = (dec_cnt & 1) ? "odd" : "even";
                            printf("     Frame %d (btn=%X): decrypt=0x%08X cnt=%05X (%s)\n",
                                   j + 1, fix[j] & 0xF, cands[i].dec[j], dec_cnt, par);
                        }
                    }
                    if (count > TOP_SHOW)
                        printf("  ... and %d more in report\n", count - TOP_SHOW);
                    printf("----------------------------------------------------------\n");
                }

                fclose(fp);
                free(cands);
            } else {
                fprintf(fp, "Too many to collect (limit=%d)\n", LIST_LIMIT);
                fclose(fp);
                printf("  Too many to list (limit=%d). Try with more frames.\n", LIST_LIMIT);
                printf("  Full report: %s\n", fname);
            }
        }
    }

    return 0;
}
