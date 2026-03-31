#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

typedef struct {
    uint32_t pe_off;
    uint32_t opt_off;
    uint32_t dllchars_off;
    uint16_t dllchars_old;
} pe_ctx_t;

static uint16_t u16le(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t u32le(const uint8_t *p) {
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void put_u16le(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xffu);
    p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static uint16_t nx_flag(void) {
    return (uint16_t)((0x7272u ^ 0x7372u) & 0xffffu); /* 0x0100 */
}

static uint32_t pe_sig(void) {
    return (uint32_t)(0x11223344u ^ 0x11223314u); /* 0x00000050 ('P' low byte) helper */
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage:\n"
            "  %s apply  <target> [--backup-dir <dir>]\n"
            "  %s revert <target> [--backup <file>]\n"
            "\n"
            "Behavior:\n"
            "  apply:  sets NX_COMPAT (0x0100), writes backup + metadata\n"
            "  revert: restores from backup metadata (or --backup), else clears NX_COMPAT\n",
            argv0, argv0);
}

static int read_file(const char *path, uint8_t **out_buf, size_t *out_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "open failed: %s: %s\n", path, strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "fstat failed: %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    if (st.st_size <= 0) {
        fprintf(stderr, "invalid file size: %s\n", path);
        close(fd);
        return -1;
    }

    size_t len = (size_t)st.st_size;
    uint8_t *buf = (uint8_t *)malloc(len);
    if (!buf) {
        fprintf(stderr, "malloc failed for %zu bytes\n", len);
        close(fd);
        return -1;
    }

    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "read failed: %s: %s\n", path, strerror(errno));
            free(buf);
            close(fd);
            return -1;
        }
        if (n == 0) break;
        off += (size_t)n;
    }
    close(fd);

    if (off != len) {
        fprintf(stderr, "short read: %s\n", path);
        free(buf);
        return -1;
    }

    *out_buf = buf;
    *out_len = len;
    return 0;
}

static int mk_parent_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        fprintf(stderr, "not a directory: %s\n", path);
        return -1;
    }
    if (mkdir(path, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "mkdir failed: %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY);
    if (in < 0) {
        fprintf(stderr, "open failed: %s: %s\n", src, strerror(errno));
        return -1;
    }
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out < 0) {
        fprintf(stderr, "open failed: %s: %s\n", dst, strerror(errno));
        close(in);
        return -1;
    }

    uint8_t buf[8192];
    while (1) {
        ssize_t n = read(in, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "read failed: %s: %s\n", src, strerror(errno));
            close(in);
            close(out);
            return -1;
        }
        if (n == 0) break;

        size_t off = 0;
        while (off < (size_t)n) {
            ssize_t w = write(out, buf + off, (size_t)n - off);
            if (w < 0) {
                if (errno == EINTR) continue;
                fprintf(stderr, "write failed: %s: %s\n", dst, strerror(errno));
                close(in);
                close(out);
                return -1;
            }
            off += (size_t)w;
        }
    }

    close(in);
    if (close(out) != 0) {
        fprintf(stderr, "close failed: %s: %s\n", dst, strerror(errno));
        return -1;
    }
    return 0;
}

static int dirname_from_path(const char *path, char *out, size_t out_sz) {
    const char *slash = strrchr(path, '/');
    if (!slash) {
        if (snprintf(out, out_sz, ".") >= (int)out_sz) return -1;
        return 0;
    }
    size_t n = (size_t)(slash - path);
    if (n == 0) n = 1; /* root "/" */
    if (n + 1 > out_sz) return -1;
    memcpy(out, path, n);
    out[n] = '\0';
    return 0;
}

static const char *basename_from_path(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static uint64_t fnv1a64(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    while (*s) {
        h ^= (uint8_t)*s++;
        h *= 1099511628211ULL;
    }
    return h;
}

static int write_atomic(const char *path, const uint8_t *buf, size_t len) {
    char tmp[PATH_MAX];
    if (snprintf(tmp, sizeof(tmp), "%s.tmp.XXXXXX", path) >= (int)sizeof(tmp)) {
        fprintf(stderr, "path too long: %s\n", path);
        return -1;
    }
    int fd = mkstemp(tmp);
    if (fd < 0) {
        fprintf(stderr, "mkstemp failed: %s: %s\n", tmp, strerror(errno));
        return -1;
    }

    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "write failed: %s: %s\n", tmp, strerror(errno));
            close(fd);
            unlink(tmp);
            return -1;
        }
        off += (size_t)n;
    }

    if (fsync(fd) != 0) {
        fprintf(stderr, "fsync failed: %s: %s\n", tmp, strerror(errno));
        close(fd);
        unlink(tmp);
        return -1;
    }
    if (close(fd) != 0) {
        fprintf(stderr, "close failed: %s: %s\n", tmp, strerror(errno));
        unlink(tmp);
        return -1;
    }

    if (rename(tmp, path) != 0) {
        fprintf(stderr, "rename failed: %s -> %s: %s\n", tmp, path, strerror(errno));
        unlink(tmp);
        return -1;
    }
    return 0;
}

static int inspect_pe(const uint8_t *buf, size_t len, pe_ctx_t *ctx) {
    if (len < 0x100) {
        fprintf(stderr, "not a valid PE: file too small\n");
        return -1;
    }
    if (buf[0] != 'M' || buf[1] != 'Z') {
        fprintf(stderr, "not a PE file: missing MZ header\n");
        return -1;
    }

    uint32_t pe_off = u32le(buf + 0x3c);
    if ((uint64_t)pe_off + 0x18 >= len) {
        fprintf(stderr, "invalid PE offset\n");
        return -1;
    }
    if (u32le(buf + pe_off) != (pe_sig() | ('E' << 8))) { /* 'PE\\0\\0' as low word 0x4550 */
        if (u32le(buf + pe_off) != 0x00004550u) {
            fprintf(stderr, "not a PE file: missing PE signature\n");
            return -1;
        }
    }

    uint32_t opt_off = pe_off + 24;
    if ((uint64_t)opt_off + 2 >= len) {
        fprintf(stderr, "invalid optional header offset\n");
        return -1;
    }

    uint16_t magic = u16le(buf + opt_off);
    uint32_t dll_off = 0;
    if (magic == 0x10b) {
        dll_off = opt_off + 0x46;
    } else if (magic == 0x20b) {
        dll_off = opt_off + 0x5e;
    } else {
        fprintf(stderr, "unsupported PE optional header magic: 0x%04x\n", magic);
        return -1;
    }

    if ((uint64_t)dll_off + 2 > len) {
        fprintf(stderr, "invalid DllCharacteristics offset\n");
        return -1;
    }

    ctx->pe_off = pe_off;
    ctx->opt_off = opt_off;
    ctx->dllchars_off = dll_off;
    ctx->dllchars_old = u16le(buf + dll_off);
    return 0;
}

static int write_meta(const char *target, const char *backup, uint16_t old_flags, uint16_t new_flags) {
    char meta_path[PATH_MAX];
    if (snprintf(meta_path, sizeof(meta_path), "%s.tahoe.meta", target) >= (int)sizeof(meta_path)) {
        fprintf(stderr, "meta path too long\n");
        return -1;
    }
    FILE *f = fopen(meta_path, "wb");
    if (!f) {
        fprintf(stderr, "fopen failed: %s: %s\n", meta_path, strerror(errno));
        return -1;
    }
    fprintf(f, "v=1\n");
    fprintf(f, "backup=%s\n", backup);
    fprintf(f, "old=0x%04x\n", old_flags);
    fprintf(f, "new=0x%04x\n", new_flags);
    fclose(f);
    return 0;
}

static int read_meta_backup(const char *target, char *out_backup, size_t out_sz) {
    char meta_path[PATH_MAX];
    if (snprintf(meta_path, sizeof(meta_path), "%s.tahoe.meta", target) >= (int)sizeof(meta_path)) return -1;

    FILE *f = fopen(meta_path, "rb");
    if (!f) return -1;

    char line[PATH_MAX + 32];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "backup=", 7) == 0) {
            char *v = line + 7;
            size_t n = strlen(v);
            while (n > 0 && (v[n - 1] == '\n' || v[n - 1] == '\r')) {
                v[--n] = '\0';
            }
            if (n + 1 > out_sz) {
                fclose(f);
                return -1;
            }
            memcpy(out_backup, v, n + 1);
            found = 1;
            break;
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

static int create_backup_path(const char *target, const char *backup_dir_opt, char *out, size_t out_sz) {
    char dir[PATH_MAX];
    if (backup_dir_opt && backup_dir_opt[0]) {
        if (snprintf(dir, sizeof(dir), "%s", backup_dir_opt) >= (int)sizeof(dir)) return -1;
    } else {
        char parent[PATH_MAX];
        if (dirname_from_path(target, parent, sizeof(parent)) != 0) return -1;
        if (snprintf(dir, sizeof(dir), "%s/.tahoe-patch", parent) >= (int)sizeof(dir)) return -1;
    }

    if (mk_parent_dir(dir) != 0) return -1;

    uint64_t h = fnv1a64(target);
    uint64_t t = (uint64_t)time(NULL);
    const char *base = basename_from_path(target);
    if (snprintf(out, out_sz, "%s/%s.%016" PRIx64 ".%016" PRIx64 ".bak", dir, base, h, t) >= (int)out_sz) {
        return -1;
    }
    return 0;
}

static int cmd_apply(const char *target, const char *backup_dir_opt) {
    uint8_t *buf = NULL;
    size_t len = 0;
    if (read_file(target, &buf, &len) != 0) return 1;

    pe_ctx_t ctx;
    if (inspect_pe(buf, len, &ctx) != 0) {
        free(buf);
        return 1;
    }

    uint16_t before = ctx.dllchars_old;
    uint16_t after = (uint16_t)(before | nx_flag());
    if (before == after) {
        printf("Already patched (NX bit already set): %s\n", target);
        free(buf);
        return 0;
    }

    char backup_path[PATH_MAX];
    if (create_backup_path(target, backup_dir_opt, backup_path, sizeof(backup_path)) != 0) {
        fprintf(stderr, "failed to create backup path\n");
        free(buf);
        return 1;
    }
    if (copy_file(target, backup_path) != 0) {
        free(buf);
        return 1;
    }

    put_u16le(buf + ctx.dllchars_off, after);
    if (write_atomic(target, buf, len) != 0) {
        free(buf);
        return 1;
    }
    free(buf);

    if (write_meta(target, backup_path, before, after) != 0) {
        fprintf(stderr, "warning: patched, but failed to write metadata\n");
    }

    printf("Patched: %s\n", target);
    printf("DllCharacteristics: 0x%04x -> 0x%04x\n", before, after);
    printf("Backup: %s\n", backup_path);
    return 0;
}

static int cmd_revert(const char *target, const char *backup_opt) {
    char backup[PATH_MAX];
    backup[0] = '\0';

    if (backup_opt && backup_opt[0]) {
        if (snprintf(backup, sizeof(backup), "%s", backup_opt) >= (int)sizeof(backup)) {
            fprintf(stderr, "backup path too long\n");
            return 1;
        }
    } else {
        (void)read_meta_backup(target, backup, sizeof(backup));
    }

    if (backup[0] != '\0') {
        struct stat st;
        if (stat(backup, &st) == 0 && S_ISREG(st.st_mode)) {
            if (copy_file(backup, target) != 0) return 1;
            printf("Reverted from backup: %s\n", backup);
            return 0;
        }
        fprintf(stderr, "warning: backup not found, falling back to flag clear: %s\n", backup);
    }

    uint8_t *buf = NULL;
    size_t len = 0;
    if (read_file(target, &buf, &len) != 0) return 1;

    pe_ctx_t ctx;
    if (inspect_pe(buf, len, &ctx) != 0) {
        free(buf);
        return 1;
    }

    uint16_t before = ctx.dllchars_old;
    uint16_t after = (uint16_t)(before & (uint16_t)(~nx_flag()));
    put_u16le(buf + ctx.dllchars_off, after);
    if (write_atomic(target, buf, len) != 0) {
        free(buf);
        return 1;
    }
    free(buf);

    printf("Reverted by clearing NX bit: %s\n", target);
    printf("DllCharacteristics: 0x%04x -> 0x%04x\n", before, after);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];
    const char *target = argv[2];
    const char *backup_dir_opt = NULL;
    const char *backup_opt = NULL;

    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--backup-dir") == 0 && i + 1 < argc) {
            backup_dir_opt = argv[++i];
        } else if (strcmp(argv[i], "--backup") == 0 && i + 1 < argc) {
            backup_opt = argv[++i];
        } else {
            fprintf(stderr, "unknown argument: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    if (strcmp(cmd, "apply") == 0) {
        return cmd_apply(target, backup_dir_opt);
    }
    if (strcmp(cmd, "revert") == 0) {
        return cmd_revert(target, backup_opt);
    }

    fprintf(stderr, "unknown command: %s\n", cmd);
    usage(argv[0]);
    return 1;
}
