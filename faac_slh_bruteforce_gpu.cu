// FAAC SLH seed brute-force - CUDA (GPU)
// For 1-2 frames: finds ALL candidate seeds, shows top 50, saves full report
// For 3+ frames: fast path, stops at first match (unique result)
// 
// Compile (recommended, clang++): clang++ --cuda-gpu-arch=sm_61 -O3 -o faac_gpu faac_slh_bruteforce_gpu.cu -L/opt/cuda/lib64 -lcuda -lcudart
// Compile (nvcc, if compatible with your GCC): nvcc -O3 -o faac_gpu faac_slh_bruteforce_gpu.cu
// Run:     ./faac_gpu <mfkey_hex> <data1_hex> [data2_hex ... dataN_hex]

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <cuda_runtime.h>

#define KEELOQ_NLF 0x3A5C742E
#define MAX_FRAMES 16
#define MAX_DUMP 1048576
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

static inline uint8_t g5_host(uint32_t x, uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e) {
    return bit(x, a) | (bit(x, b) << 1) | (bit(x, c) << 2) | (bit(x, d) << 3) | (bit(x, e) << 4);
}

static inline uint32_t keeloq_encrypt_host(uint32_t data, uint64_t key) {
    uint32_t x = data;
    for (int r = 0; r < 528; r++)
        x = (x >> 1) | ((bit(x, 0) ^ bit(x, 16) ^ bit(key, r & 63) ^ bit(KEELOQ_NLF, g5_host(x, 1, 9, 20, 26, 31))) << 31);
    return x;
}

static inline uint32_t keeloq_decrypt_host(uint32_t data, uint64_t key) {
    uint32_t x = data;
    for (int r = 0; r < 528; r++)
        x = (x << 1) | (bit(x, 31) ^ bit(x, 15) ^ bit(key, (15 - r) & 63) ^ bit(KEELOQ_NLF, g5_host(x, 0, 8, 19, 25, 30)));
    return x;
}

static inline uint64_t faac_learning_host(uint32_t seed, uint64_t mfkey) {
    uint16_t hs = seed >> 16;
    uint32_t lsb = ((uint32_t)hs << 16) | 0x544D;
    return ((uint64_t)keeloq_encrypt_host(seed, mfkey) << 32) | keeloq_encrypt_host(lsb, mfkey);
}

// ---------- CUDA DEVICE ----------
__device__ inline uint8_t g5_dev(uint32_t x, uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint8_t e) {
    return ((x >> a) & 1) | (((x >> b) & 1) << 1) | (((x >> c) & 1) << 2) |
           (((x >> d) & 1) << 3) | (((x >> e) & 1) << 4);
}

__device__ inline uint32_t keeloq_decrypt_dev(uint32_t data, uint64_t key) {
    uint32_t x = data;
    for (int r = 0; r < 528; r++) {
        uint32_t fb = ((x >> 31) & 1) ^ ((x >> 15) & 1) ^ ((key >> ((15 - r) & 63)) & 1) ^
                     ((KEELOQ_NLF >> g5_dev(x, 0, 8, 19, 25, 30)) & 1);
        x = (x << 1) | fb;
    }
    return x;
}

__device__ inline uint32_t keeloq_encrypt_dev(uint32_t data, uint64_t key) {
    uint32_t x = data;
    for (int r = 0; r < 528; r++) {
        uint32_t fb = (x & 1) ^ ((x >> 16) & 1) ^ ((key >> (r & 63)) & 1) ^
                     ((KEELOQ_NLF >> g5_dev(x, 1, 9, 20, 26, 31)) & 1);
        x = (x >> 1) | (fb << 31);
    }
    return x;
}

__device__ inline uint64_t faac_learning_dev(uint32_t seed, uint64_t mfkey) {
    uint16_t hs = seed >> 16;
    uint32_t lsb = ((uint32_t)hs << 16) | 0x544D;
    return ((uint64_t)keeloq_encrypt_dev(seed, mfkey) << 32) | keeloq_encrypt_dev(lsb, mfkey);
}

__device__ inline int validate_dev(uint32_t decrypt, uint32_t code_fix) {
    uint8_t n[8];
    for (int i = 7; i >= 0; i--)
        n[7 - i] = (code_fix >> (i * 4)) & 0xF;
    uint32_t top = decrypt >> 20;
    uint32_t even = (n[6] << 8) | (n[7] << 4) | n[5];
    uint32_t odd  = (n[2] << 8) | (n[3] << 4) | n[4];
    return (top == even || top == odd);
}

__global__ void search_kernel(
    uint64_t mfkey,
    uint32_t *fix_arr, uint32_t *hop_arr, int nf,
    uint32_t *out_seed, int *out_found) {

    uint64_t idx = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    uint64_t stride = gridDim.x * (uint64_t)blockDim.x;

    for (uint64_t s = idx; s < (1ULL << 32); s += stride) {
        if (*out_found) return;
        uint32_t seed = (uint32_t)s;
        uint64_t man = faac_learning_dev(seed, mfkey);
        int ok = 1;
        for (int i = 0; i < nf; i++) {
            uint32_t dec = keeloq_decrypt_dev(hop_arr[i], man);
            if (!validate_dev(dec, fix_arr[i])) { ok = 0; break; }
        }
        if (ok && atomicCAS(out_found, 0, 1) == 0) {
            *out_seed = seed;
        }
    }
}

__global__ void count_collect_kernel(
    uint64_t mfkey,
    uint32_t *fix_arr, uint32_t *hop_arr, int nf,
    uint32_t *out_seeds, uint32_t *out_count, uint32_t max_coll) {

    uint64_t idx = blockIdx.x * (uint64_t)blockDim.x + threadIdx.x;
    uint64_t stride = gridDim.x * (uint64_t)blockDim.x;

    for (uint64_t s = idx; s < (1ULL << 32); s += stride) {
        uint32_t seed = (uint32_t)s;
        uint64_t man = faac_learning_dev(seed, mfkey);
        int ok = 1;
        for (int i = 0; i < nf; i++) {
            uint32_t dec = keeloq_decrypt_dev(hop_arr[i], man);
            if (!validate_dev(dec, fix_arr[i])) { ok = 0; break; }
        }
        if (ok) {
            uint32_t pos = atomicAdd(out_count, 1);
            if (pos < max_coll) {
                out_seeds[pos] = seed;
            }
        }
    }
}

// ---------- HOST ----------
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

    uint32_t *d_fix, *d_hop;
    cudaMalloc(&d_fix, nf * sizeof(uint32_t));
    cudaMalloc(&d_hop, nf * sizeof(uint32_t));
    cudaMemcpy(d_fix, fix, nf * sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaMemcpy(d_hop, hop, nf * sizeof(uint32_t), cudaMemcpyHostToDevice);

    int threads = 256;
    int blocks;
    cudaDeviceGetAttribute(&blocks, cudaDevAttrMultiProcessorCount, 0);
    blocks *= 32;

    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);

    if (use_fast) {
        printf("3+ frames -- unique seed expected, fast path.\n");
        uint32_t *d_out_seed;
        int *d_out_found;
        cudaMalloc(&d_out_seed, sizeof(uint32_t));
        cudaMalloc(&d_out_found, sizeof(int));
        int h_found = 0;
        uint32_t h_seed = 0;
        cudaMemcpy(d_out_found, &h_found, sizeof(int), cudaMemcpyHostToDevice);
        cudaMemcpy(d_out_seed, &h_seed, sizeof(uint32_t), cudaMemcpyHostToDevice);

        printf("Launching %d blocks x %d threads on %d frames...\n", blocks, threads, nf);
        cudaEventRecord(start);
        search_kernel<<<blocks, threads>>>(mfkey, d_fix, d_hop, nf, d_out_seed, d_out_found);
        cudaDeviceSynchronize();
        cudaEventRecord(stop);
        cudaEventSynchronize(stop);
        float ms = 0;
        cudaEventElapsedTime(&ms, start, stop);

        cudaMemcpy(&h_found, d_out_found, sizeof(int), cudaMemcpyDeviceToHost);
        cudaMemcpy(&h_seed, d_out_seed, sizeof(uint32_t), cudaMemcpyDeviceToHost);

        // Build report
        FILE *fp = fopen(fname, "w");
        fprintf(fp, "FAAC SLH Seed Brute-Force Report\n");
        fprintf(fp, "MFKey: 0x%016lX\n", mfkey);
        fprintf(fp, "Frames: %d\n", nf);
        for (int i = 0; i < nf; i++)
            fprintf(fp, "  Frame %d: Fix=0x%08X Hop=0x%08X\n", i + 1, fix[i], hop[i]);
        fprintf(fp, "Search mode: fast path (3+ frames)\n");
        fprintf(fp, "Time: %.2f seconds\n", ms / 1000.0f);

        if (h_found) {
            uint64_t man = faac_learning_host(h_seed, mfkey);
            fprintf(fp, "\n*** SEED = 0x%08X (100%% confidence, unique) ***\n", h_seed);
            for (int i = 0; i < nf; i++) {
                uint32_t dec = keeloq_decrypt_host(hop[i], man);
                fprintf(fp, "  Frame %d: decrypt=0x%08X cnt=%05X\n", i + 1, dec, dec & 0xFFFFF);
            }
        } else {
            fprintf(fp, "\nNot found. Wrong mfkey or protocol?\n");
        }
        fclose(fp);

        // Terminal output
        if (h_found) {
            uint64_t man = faac_learning_host(h_seed, mfkey);
            printf("\n*** SEED = 0x%08X *** (100%% confidence, %.2f seconds)\n", h_seed, ms / 1000.0f);
            printf("  Full report: %s\n", fname);
            for (int i = 0; i < nf; i++) {
                uint32_t dec = keeloq_decrypt_host(hop[i], man);
                printf("  Frame %d: decrypt=0x%08X cnt=%05X\n", i + 1, dec, dec & 0xFFFFF);
            }
        } else {
            printf("\nNot found (%.2f seconds). Wrong mfkey or protocol?\n", ms / 1000.0f);
        }

        cudaFree(d_out_seed); cudaFree(d_out_found);
    } else {
        printf("1-2 frames -- collecting all candidate seeds.\n");
        printf("  %d distinct button%s\n",
               same_btn ? 1 : (nf > 1 ? 2 : 1),
               same_btn ? "" : "s");
        printf("Launching %d blocks x %d threads on %d frames...\n", blocks, threads, nf);

        uint32_t *d_seeds, *d_count;
        cudaMalloc(&d_seeds, MAX_DUMP * sizeof(uint32_t));
        cudaMalloc(&d_count, sizeof(uint32_t));
        uint32_t zero = 0;
        cudaMemcpy(d_count, &zero, sizeof(uint32_t), cudaMemcpyHostToDevice);

        cudaEventRecord(start);
        count_collect_kernel<<<blocks, threads>>>(mfkey, d_fix, d_hop, nf, d_seeds, d_count, MAX_DUMP);
        cudaDeviceSynchronize();
        cudaEventRecord(stop);
        cudaEventSynchronize(stop);
        float ms = 0;
        cudaEventElapsedTime(&ms, start, stop);

        uint32_t h_count;
        cudaMemcpy(&h_count, d_count, sizeof(uint32_t), cudaMemcpyDeviceToHost);

        printf("\nFound %u candidates (%.2f seconds)\n", h_count, ms / 1000.0f);

        // Terminal & report
        FILE *fp = fopen(fname, "w");
        fprintf(fp, "FAAC SLH Seed Brute-Force Report\n");
        fprintf(fp, "MFKey: 0x%016lX\n", mfkey);
        fprintf(fp, "Frames: %d\n", nf);
        for (int i = 0; i < nf; i++)
            fprintf(fp, "  Frame %d: Fix=0x%08X Hop=0x%08X\n", i + 1, fix[i], hop[i]);
        fprintf(fp, "Search mode: collect (1-2 frames)\n");
        fprintf(fp, "Time: %.2f seconds\n", ms / 1000.0f);

        if (h_count == 0) {
            fprintf(fp, "\nNo candidates found.\n");
            printf("No candidates found. Wrong mfkey or protocol?\n");
            fclose(fp);
        } else {
            float eff_bits = 32.0f - log2f((float)h_count);
            fprintf(fp, "\nTotal candidates: %u\n", h_count);
            fprintf(fp, "Effective bits determined: %.1f / 32\n", eff_bits);

            CandSort *cands = NULL;
            if (h_count <= LIST_LIMIT) {
                uint32_t *h_seeds = (uint32_t*)malloc(h_count * sizeof(uint32_t));
                cudaMemcpy(h_seeds, d_seeds, h_count * sizeof(uint32_t), cudaMemcpyDeviceToHost);

                cands = (CandSort*)malloc(h_count * sizeof(CandSort));
                for (uint32_t i = 0; i < h_count; i++) {
                    cands[i].seed = h_seeds[i];
                    uint64_t man = faac_learning_host(h_seeds[i], mfkey);
                    for (int j = 0; j < nf; j++)
                        cands[i].dec[j] = keeloq_decrypt_host(hop[j], man);
                    if (same_btn && nf == 2)
                        cands[i].gap = abs((int)(cands[i].dec[0] & 0xFFFFF) - (int)(cands[i].dec[1] & 0xFFFFF));
                    else
                        cands[i].gap = -1;
                }
                free(h_seeds);

                int sort_by_gap = (same_btn && nf == 2);
                if (sort_by_gap) {
                    qsort(cands, h_count, sizeof(CandSort), cmp_by_gap);
                    float total_score = 0;
                    for (uint32_t i = 0; i < h_count; i++)
                        total_score += 1.0f / (1.0f + cands[i].gap / 10.0f);
                    for (uint32_t i = 0; i < h_count; i++)
                        cands[i].pct = 100.0f / (1.0f + cands[i].gap / 10.0f) / total_score;

                    // Write full report
                    fprintf(fp, "Sorted by counter gap (smaller = more likely):\n\n");
                    for (uint32_t i = 0; i < h_count; i++) {
                        fprintf(fp, "%4u: SEED=0x%08X gap=%d (%.4f%%)\n", i + 1, cands[i].seed, cands[i].gap, cands[i].pct);
                        for (int j = 0; j < nf; j++)
                            fprintf(fp, "     Frame %d (btn=%X): decrypt=0x%08X cnt=%05X\n",
                                    j + 1, fix[j] & 0xF, cands[i].dec[j], cands[i].dec[j] & 0xFFFFF);
                    }

                    // Terminal: top 50
                    int show = h_count < TOP_SHOW ? h_count : TOP_SHOW;
                    printf("\n  Top %d / %u candidates (sorted by gap):\n", show, h_count);
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
                    if (h_count > TOP_SHOW)
                        printf("  ... and %u more in report\n", h_count - TOP_SHOW);
                    printf("----------------------------------------------------------\n");
                } else {
                    qsort(cands, h_count, sizeof(CandSort), cmp_by_seed);
                    for (uint32_t i = 0; i < h_count; i++)
                        cands[i].pct = 100.0f / h_count;

                    // Write full report
                    fprintf(fp, "All %u candidates (sorted by seed, each = %.4f%%):\n\n", h_count, 100.0 / h_count);
                    for (uint32_t i = 0; i < h_count; i++) {
                        fprintf(fp, "%4u: SEED=0x%08X\n", i + 1, cands[i].seed);
                        for (int j = 0; j < nf; j++)
                            fprintf(fp, "     Frame %d (btn=%X): decrypt=0x%08X cnt=%05X\n",
                                    j + 1, fix[j] & 0xF, cands[i].dec[j], cands[i].dec[j] & 0xFFFFF);
                    }

                    // Terminal: top 50
                    int show = h_count < TOP_SHOW ? h_count : TOP_SHOW;
                    printf("\n  Top %d / %u candidates (sorted by seed):\n", show, h_count);
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
                    if (h_count > TOP_SHOW)
                        printf("  ... and %u more in report\n", h_count - TOP_SHOW);
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

        cudaFree(d_seeds); cudaFree(d_count);
    }

    cudaFree(d_fix); cudaFree(d_hop);
    cudaEventDestroy(start); cudaEventDestroy(stop);
    return 0;
}
