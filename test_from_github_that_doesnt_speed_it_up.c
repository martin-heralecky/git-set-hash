#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define roll(val, n) (((val) << (n)) | ((val) >> (32 - (n))))

struct context {
	uint32_t h0, h1, h2, h3, h4;
};

void init(struct context *ctx)
{
	ctx->h0 = 0x67452301;
	ctx->h1 = 0xefcdab89;
	ctx->h2 = 0x98badcfe;
	ctx->h3 = 0x10325476;
	ctx->h4 = 0xc3d2e1f0;
}

void process_block(struct context *ctx, uint8_t *chunk)
{
	uint32_t a, b, c, d, e, temp, w[16];

	memcpy(w, chunk, 64);

	a = ctx->h0;
	b = ctx->h1;
	c = ctx->h2;
	d = ctx->h3;
	e = ctx->h4;

#define R0(a, b, c, d, e, i) e += roll(a, 5) + ((b & (c ^ d)) ^ d)       + (w[i] = (roll(w[i],24)&0xFF00FF00)|(roll(w[i],8)&0x00FF00FF)) + 0x5a827999; b = roll(b, 30);
#define R1(a, b, c, d, e, i) e += roll(a, 5) + ((b & (c ^ d)) ^ d)       + (w[i&15] = roll(w[(i+13)&15]^w[(i+8)&15]^w[(i+2)&15]^w[i&15],1)) + 0x5a827999; b = roll(b, 30);
#define R2(a, b, c, d, e, i) e += roll(a, 5) + (b ^ c ^ d)               + (w[i&15] = roll(w[(i+13)&15]^w[(i+8)&15]^w[(i+2)&15]^w[i&15],1)) + 0x6ed9eba1; b = roll(b, 30);
#define R3(a, b, c, d, e, i) e += roll(a, 5) + (((b | c) & d) | (b & c)) + (w[i&15] = roll(w[(i+13)&15]^w[(i+8)&15]^w[(i+2)&15]^w[i&15],1)) + 0x8f1bbcdc; b = roll(b, 30);
#define R4(a, b, c, d, e, i) e += roll(a, 5) + (b ^ c ^ d)               + (w[i&15] = roll(w[(i+13)&15]^w[(i+8)&15]^w[(i+2)&15]^w[i&15],1)) + 0xca62c1d6; b = roll(b, 30);

	R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
	R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
	R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);

	ctx->h0 += a;
	ctx->h1 += b;
	ctx->h2 += c;
	ctx->h3 += d;
	ctx->h4 += e;
}

void my_sha1(const unsigned char *data, unsigned int size, unsigned char *out)
{
	struct context ctx;
	init(&ctx);

	uint8_t chunk[64];
	int di = 0;

	while (size - di >= 64) {
		// todo use chunk only in last chunk, otherwise use data directly
		memcpy(chunk, data + di, 64);
		process_block(&ctx, chunk);
		di += 64;
	}

	memcpy(chunk, data + di, size - di);
	chunk[size - di] = 0x80;
	memset(chunk + (size - di) + 1, 0, 64 - (size - di) - 1 - 4);
	chunk[60] = size >> 21;
	chunk[61] = size >> 13;
	chunk[62] = size >> 5;
	chunk[63] = size << 3;

	process_block(&ctx, chunk);

	out[0] = ctx.h0 >> 24;
	out[1] = ctx.h0 >> 16;
	out[2] = ctx.h0 >> 8;
	out[3] = ctx.h0;
	out[4] = ctx.h1 >> 24;
	out[5] = ctx.h1 >> 16;
	out[6] = ctx.h1 >> 8;
	out[7] = ctx.h1;
	out[8] = ctx.h2 >> 24;
	out[9] = ctx.h2 >> 16;
	out[10] = ctx.h2 >> 8;
	out[11] = ctx.h2;
	out[12] = ctx.h3 >> 24;
	out[13] = ctx.h3 >> 16;
	out[14] = ctx.h3 >> 8;
	out[15] = ctx.h3;
	out[16] = ctx.h4 >> 24;
	out[17] = ctx.h4 >> 16;
	out[18] = ctx.h4 >> 8;
	out[19] = ctx.h4;
}

void openssl_sha1(const unsigned char *data, unsigned int size, unsigned char *out)
{
	SHA1(data, size, out);
}

int main(int argc, char **argv)
{
	int num = atoi(argv[1]);

	const char *data = "tto be hashed this is a value to be hashed qw";
	unsigned int data_size = strlen(data);
	unsigned char hash[20];

	printf("data: %s\n", data);

	struct timeval start, end;
	double dur;

	gettimeofday(&start, NULL);
	SHA_CTX c;
	for (int i = 0; i < num; ++i) {
		SHA1_Init(&c);
		SHA1_Update(&c, (const unsigned char *)data, data_size);
		SHA1_Final(hash, &c);
	}
	gettimeofday(&end, NULL);

	dur = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)) / 1000000.0;

	printf("SHA1:    %.4fs (hash: ", dur);
	for (int i = 0; i < 20; ++i) {
		printf("%02x", hash[i]);
	}
	printf(")\n");

	memset(hash, 0, 20);

	// -------------------------------------------------------------------

	gettimeofday(&start, NULL);
	for (int i = 0; i < num; ++i) {
		my_sha1((const unsigned char *)data, data_size, hash);
	}
	gettimeofday(&end, NULL);

	dur = ((end.tv_sec * 1000000 + end.tv_usec) - (start.tv_sec * 1000000 + start.tv_usec)) / 1000000.0;

	printf("my_sha1: %.4fs (hash: ", dur);
	for (int i = 0; i < 20; ++i) {
		printf("%02x", hash[i]);
	}
	printf(")\n");

	return 0;
}
