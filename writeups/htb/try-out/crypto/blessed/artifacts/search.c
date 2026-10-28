/*
 * Meet-in-the-middle search for the low 32 bits of a P-256 point.
 *
 * Given the high 224 bits of x and y of W = (x, y) on y^2 = x^3 - 3x + b (mod p),
 * find u, v in [0, 2^32) such that (X0 + u)^3 - 3(X0 + u) + b == (Y0 + v)^2 (mod p),
 * where X0 = xhi << 32 and Y0 = yhi << 32.
 *
 * Both sides are evaluated with finite differences (additions only). Keys are the low
 * 64 bits of the residue; the search is split into 2^B passes by the top B bits of the key
 * so that each pass holds only one bucket in memory.
 *
 * usage: search <B> <pass> < init.txt
 * init.txt: p, six (=6), f0, d1, d2, g0, s0 as hex (one per line, in that order).
 * Output: candidate "u v" pairs (decimal), to be verified exactly by the caller.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct { uint64_t l[4]; } u256;  /* little-endian 64-bit limbs */

static u256 P;

static int parse_hex(const char *s, u256 *out) {
    memset(out, 0, sizeof(*out));
    size_t n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ')) n--;
    if (n > 64) return -1;
    for (size_t i = 0; i < n; i++) {
        char c = s[n - 1 - i];
        uint64_t d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return -1;
        out->l[i / 16] |= d << ((i % 16) * 4);
    }
    return 0;
}

/* r = a + b mod p */
static inline void addm(u256 *r, const u256 *a, const u256 *b) {
    unsigned __int128 c = 0;
    u256 s;
    for (int i = 0; i < 4; i++) {
        c += (unsigned __int128)a->l[i] + b->l[i];
        s.l[i] = (uint64_t)c;
        c >>= 64;
    }
    u256 t;
    unsigned __int128 br = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 d = (unsigned __int128)s.l[i] - P.l[i] - br;
        t.l[i] = (uint64_t)d;
        br = (d >> 64) & 1;
    }
    /* s >= p (no borrow) or the sum overflowed 2^256: take t = s - p */
    if (c || !br) *r = t;
    else *r = s;
}

typedef struct { uint64_t key; uint32_t idx; } entry;

typedef struct { entry *a; size_t n, cap; } vec;

static void push(vec *v, uint64_t key, uint32_t idx) {
    if (v->n == v->cap) {
        v->cap = v->cap ? v->cap * 2 : (1 << 20);
        v->a = realloc(v->a, v->cap * sizeof(entry));
        if (!v->a) { perror("realloc"); exit(1); }
    }
    v->a[v->n].key = key;
    v->a[v->n].idx = idx;
    v->n++;
}

static int cmp(const void *x, const void *y) {
    uint64_t a = ((const entry *)x)->key, b = ((const entry *)y)->key;
    return (a > b) - (a < b);
}

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s B pass\n", argv[0]); return 1; }
    int B = atoi(argv[1]);
    uint64_t pass = strtoull(argv[2], NULL, 10);

    char line[256];
    u256 six, f, d1, d2, g, s;
    int have = 0;
    u256 *vals[] = { &P, &six, &f, &d1, &d2, &g, &s };
    for (int i = 0; i < 7; i++) {
        if (!fgets(line, sizeof(line), stdin) || parse_hex(line, vals[i]) < 0) {
            fprintf(stderr, "bad init line %d\n", i);
            return 1;
        }
        have++;
    }

    const uint64_t N = 1ULL << 32;
    vec U = {0}, V = {0};
    int shift = 64 - B;

    /* u side: F(X0 + u) */
    u256 cur = f, D1 = d1, D2 = d2;
    for (uint64_t u = 0; u < N; u++) {
        if ((cur.l[0] >> shift) == pass) push(&U, cur.l[0], (uint32_t)u);
        addm(&cur, &cur, &D1);
        addm(&D1, &D1, &D2);
        addm(&D2, &D2, &six);
    }

    /* v side: (Y0 + v)^2 mod p, with step s_v = 2(Y0 + v) + 1 */
    cur = g;
    u256 S = s, two = {{2, 0, 0, 0}};
    for (uint64_t v = 0; v < N; v++) {
        if ((cur.l[0] >> shift) == pass) push(&V, cur.l[0], (uint32_t)v);
        addm(&cur, &cur, &S);
        addm(&S, &S, &two);
    }

    qsort(U.a, U.n, sizeof(entry), cmp);
    qsort(V.a, V.n, sizeof(entry), cmp);
    fprintf(stderr, "pass %llu: %zu u-keys, %zu v-keys\n", (unsigned long long)pass, U.n, V.n);

    size_t i = 0, j = 0;
    while (i < U.n && j < V.n) {
        uint64_t a = U.a[i].key, b = V.a[j].key;
        if (a < b) { i++; continue; }
        if (a > b) { j++; continue; }
        size_t i2 = i, j2 = j;
        while (i2 < U.n && U.a[i2].key == a) i2++;
        while (j2 < V.n && V.a[j2].key == a) j2++;
        for (size_t x = i; x < i2; x++)
            for (size_t y = j; y < j2; y++)
                printf("%u %u\n", U.a[x].idx, V.a[y].idx);
        i = i2;
        j = j2;
    }
    free(U.a);
    free(V.a);
    return 0;
}
