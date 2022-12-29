#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define roll(val, n) (((val) << (n)) | ((val) >> (32 - (n))))

typedef uint32_t v4ui __attribute__ ((vector_size (16)));

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

void sha1_ni_transform(uint32_t *digest, const void *data, uint32_t block_count);
void process_block(struct context *ctx, uint8_t *chunk)
{
	sha1_ni_transform((uint32_t *)ctx, chunk, 1);
	return;

	typedef union {
		uint32_t w[80];
		v4ui v[20];
	} block;
	uint32_t a, b, c, d, e, temp;
	block w;

	w.w[0]  = chunk[0]  << 24 | chunk[1]  << 16 | chunk[2]  << 8 | chunk[3];
	w.w[1]  = chunk[4]  << 24 | chunk[5]  << 16 | chunk[6]  << 8 | chunk[7];
	w.w[2]  = chunk[8]  << 24 | chunk[9]  << 16 | chunk[10] << 8 | chunk[11];
	w.w[3]  = chunk[12] << 24 | chunk[13] << 16 | chunk[14] << 8 | chunk[15];
	w.w[4]  = chunk[16] << 24 | chunk[17] << 16 | chunk[18] << 8 | chunk[19];
	w.w[5]  = chunk[20] << 24 | chunk[21] << 16 | chunk[22] << 8 | chunk[23];
	w.w[6]  = chunk[24] << 24 | chunk[25] << 16 | chunk[26] << 8 | chunk[27];
	w.w[7]  = chunk[28] << 24 | chunk[29] << 16 | chunk[30] << 8 | chunk[31];
	w.w[8]  = chunk[32] << 24 | chunk[33] << 16 | chunk[34] << 8 | chunk[35];
	w.w[9]  = chunk[36] << 24 | chunk[37] << 16 | chunk[38] << 8 | chunk[39];
	w.w[10] = chunk[40] << 24 | chunk[41] << 16 | chunk[42] << 8 | chunk[43];
	w.w[11] = chunk[44] << 24 | chunk[45] << 16 | chunk[46] << 8 | chunk[47];
	w.w[12] = chunk[48] << 24 | chunk[49] << 16 | chunk[50] << 8 | chunk[51];
	w.w[13] = chunk[52] << 24 | chunk[53] << 16 | chunk[54] << 8 | chunk[55];
	w.w[14] = chunk[56] << 24 | chunk[57] << 16 | chunk[58] << 8 | chunk[59];
	w.w[15] = chunk[60] << 24 | chunk[61] << 16 | chunk[62] << 8 | chunk[63];

	w.w[16] = roll(w.w[16-3] ^ w.w[16-8] ^ w.w[16-14] ^ w.w[16-16], 1);
	w.w[17] = roll(w.w[17-3] ^ w.w[17-8] ^ w.w[17-14] ^ w.w[17-16], 1);
	w.w[18] = roll(w.w[18-3] ^ w.w[18-8] ^ w.w[18-14] ^ w.w[18-16], 1);
	w.w[19] = roll(w.w[19-3] ^ w.w[19-8] ^ w.w[19-14] ^ w.w[19-16], 1);
	w.w[20] = roll(w.w[20-3] ^ w.w[20-8] ^ w.w[20-14] ^ w.w[20-16], 1);
	w.w[21] = roll(w.w[21-3] ^ w.w[21-8] ^ w.w[21-14] ^ w.w[21-16], 1);
	w.w[22] = roll(w.w[22-3] ^ w.w[22-8] ^ w.w[22-14] ^ w.w[22-16], 1);
	w.w[23] = roll(w.w[23-3] ^ w.w[23-8] ^ w.w[23-14] ^ w.w[23-16], 1);
	w.w[24] = roll(w.w[24-3] ^ w.w[24-8] ^ w.w[24-14] ^ w.w[24-16], 1);
	w.w[25] = roll(w.w[25-3] ^ w.w[25-8] ^ w.w[25-14] ^ w.w[25-16], 1);
	w.w[26] = roll(w.w[26-3] ^ w.w[26-8] ^ w.w[26-14] ^ w.w[26-16], 1);
	w.w[27] = roll(w.w[27-3] ^ w.w[27-8] ^ w.w[27-14] ^ w.w[27-16], 1);
	w.w[28] = roll(w.w[28-3] ^ w.w[28-8] ^ w.w[28-14] ^ w.w[28-16], 1);
	w.w[29] = roll(w.w[29-3] ^ w.w[29-8] ^ w.w[29-14] ^ w.w[29-16], 1);
	w.w[30] = roll(w.w[30-3] ^ w.w[30-8] ^ w.w[30-14] ^ w.w[30-16], 1);
	w.w[31] = roll(w.w[31-3] ^ w.w[31-8] ^ w.w[31-14] ^ w.w[31-16], 1);
	w.w[32] = roll(w.w[32-3] ^ w.w[32-8] ^ w.w[32-14] ^ w.w[32-16], 1);
	w.w[33] = roll(w.w[33-3] ^ w.w[33-8] ^ w.w[33-14] ^ w.w[33-16], 1);
	w.w[34] = roll(w.w[34-3] ^ w.w[34-8] ^ w.w[34-14] ^ w.w[34-16], 1);
	w.w[35] = roll(w.w[35-3] ^ w.w[35-8] ^ w.w[35-14] ^ w.w[35-16], 1);

//	v4ui va, vb, vc, vd, vr;
//	va[0] = w.w[32-6]; va[1] = w.w[33-6]; va[2] = w.w[34-6]; va[3] = w.w[35-6];
//	vb[0] = w.w[32-16]; vb[1] = w.w[33-16]; vb[2] = w.w[34-16]; vb[3] = w.w[35-16];
//	vc[0] = w.w[32-28]; vc[1] = w.w[33-28]; vc[2] = w.w[34-28]; vc[3] = w.w[35-28];
//	vd[0] = w.w[32-32]; vd[1] = w.w[33-32]; vd[2] = w.w[34-32]; vd[3] = w.w[35-32];
//	vr = va ^ vb ^ vc ^ vd;
//	*(v4ui *)(w.w + 32) = vr << 2 | (vr >> (32 - 2));

	w.w[36] = roll(w.w[36-6] ^ w.w[36-16] ^ w.w[36-28] ^ w.w[36-32], 2);
	w.w[37] = roll(w.w[37-6] ^ w.w[37-16] ^ w.w[37-28] ^ w.w[37-32], 2);
	w.w[38] = roll(w.w[38-6] ^ w.w[38-16] ^ w.w[38-28] ^ w.w[38-32], 2);
	w.w[39] = roll(w.w[39-6] ^ w.w[39-16] ^ w.w[39-28] ^ w.w[39-32], 2);
	w.w[40] = roll(w.w[40-6] ^ w.w[40-16] ^ w.w[40-28] ^ w.w[40-32], 2);
	w.w[41] = roll(w.w[41-6] ^ w.w[41-16] ^ w.w[41-28] ^ w.w[41-32], 2);
	w.w[42] = roll(w.w[42-6] ^ w.w[42-16] ^ w.w[42-28] ^ w.w[42-32], 2);
	w.w[43] = roll(w.w[43-6] ^ w.w[43-16] ^ w.w[43-28] ^ w.w[43-32], 2);
	w.w[44] = roll(w.w[44-6] ^ w.w[44-16] ^ w.w[44-28] ^ w.w[44-32], 2);
	w.w[45] = roll(w.w[45-6] ^ w.w[45-16] ^ w.w[45-28] ^ w.w[45-32], 2);
	w.w[46] = roll(w.w[46-6] ^ w.w[46-16] ^ w.w[46-28] ^ w.w[46-32], 2);
	w.w[47] = roll(w.w[47-6] ^ w.w[47-16] ^ w.w[47-28] ^ w.w[47-32], 2);
	w.w[48] = roll(w.w[48-6] ^ w.w[48-16] ^ w.w[48-28] ^ w.w[48-32], 2);
	w.w[49] = roll(w.w[49-6] ^ w.w[49-16] ^ w.w[49-28] ^ w.w[49-32], 2);
	w.w[50] = roll(w.w[50-6] ^ w.w[50-16] ^ w.w[50-28] ^ w.w[50-32], 2);
	w.w[51] = roll(w.w[51-6] ^ w.w[51-16] ^ w.w[51-28] ^ w.w[51-32], 2);
	w.w[52] = roll(w.w[52-6] ^ w.w[52-16] ^ w.w[52-28] ^ w.w[52-32], 2);
	w.w[53] = roll(w.w[53-6] ^ w.w[53-16] ^ w.w[53-28] ^ w.w[53-32], 2);
	w.w[54] = roll(w.w[54-6] ^ w.w[54-16] ^ w.w[54-28] ^ w.w[54-32], 2);
	w.w[55] = roll(w.w[55-6] ^ w.w[55-16] ^ w.w[55-28] ^ w.w[55-32], 2);
	w.w[56] = roll(w.w[56-6] ^ w.w[56-16] ^ w.w[56-28] ^ w.w[56-32], 2);
	w.w[57] = roll(w.w[57-6] ^ w.w[57-16] ^ w.w[57-28] ^ w.w[57-32], 2);
	w.w[58] = roll(w.w[58-6] ^ w.w[58-16] ^ w.w[58-28] ^ w.w[58-32], 2);
	w.w[59] = roll(w.w[59-6] ^ w.w[59-16] ^ w.w[59-28] ^ w.w[59-32], 2);
	w.w[60] = roll(w.w[60-6] ^ w.w[60-16] ^ w.w[60-28] ^ w.w[60-32], 2);
	w.w[61] = roll(w.w[61-6] ^ w.w[61-16] ^ w.w[61-28] ^ w.w[61-32], 2);
	w.w[62] = roll(w.w[62-6] ^ w.w[62-16] ^ w.w[62-28] ^ w.w[62-32], 2);
	w.w[63] = roll(w.w[63-6] ^ w.w[63-16] ^ w.w[63-28] ^ w.w[63-32], 2);
	w.w[64] = roll(w.w[64-6] ^ w.w[64-16] ^ w.w[64-28] ^ w.w[64-32], 2);
	w.w[65] = roll(w.w[65-6] ^ w.w[65-16] ^ w.w[65-28] ^ w.w[65-32], 2);
	w.w[66] = roll(w.w[66-6] ^ w.w[66-16] ^ w.w[66-28] ^ w.w[66-32], 2);
	w.w[67] = roll(w.w[67-6] ^ w.w[67-16] ^ w.w[67-28] ^ w.w[67-32], 2);
	w.w[68] = roll(w.w[68-6] ^ w.w[68-16] ^ w.w[68-28] ^ w.w[68-32], 2);
	w.w[69] = roll(w.w[69-6] ^ w.w[69-16] ^ w.w[69-28] ^ w.w[69-32], 2);
	w.w[70] = roll(w.w[70-6] ^ w.w[70-16] ^ w.w[70-28] ^ w.w[70-32], 2);
	w.w[71] = roll(w.w[71-6] ^ w.w[71-16] ^ w.w[71-28] ^ w.w[71-32], 2);
	w.w[72] = roll(w.w[72-6] ^ w.w[72-16] ^ w.w[72-28] ^ w.w[72-32], 2);
	w.w[73] = roll(w.w[73-6] ^ w.w[73-16] ^ w.w[73-28] ^ w.w[73-32], 2);
	w.w[74] = roll(w.w[74-6] ^ w.w[74-16] ^ w.w[74-28] ^ w.w[74-32], 2);
	w.w[75] = roll(w.w[75-6] ^ w.w[75-16] ^ w.w[75-28] ^ w.w[75-32], 2);
	w.w[76] = roll(w.w[76-6] ^ w.w[76-16] ^ w.w[76-28] ^ w.w[76-32], 2);
	w.w[77] = roll(w.w[77-6] ^ w.w[77-16] ^ w.w[77-28] ^ w.w[77-32], 2);
	w.w[78] = roll(w.w[78-6] ^ w.w[78-16] ^ w.w[78-28] ^ w.w[78-32], 2);
	w.w[79] = roll(w.w[79-6] ^ w.w[79-16] ^ w.w[79-28] ^ w.w[79-32], 2);

	a = ctx->h0;
	b = ctx->h1;
	c = ctx->h2;
	d = ctx->h3;
	e = ctx->h4;

	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[0]  + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[1]  + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[2]  + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[3]  + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[4]  + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[5]  + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[6]  + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[7]  + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[8]  + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[9]  + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[10] + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[11] + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[12] + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[13] + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[14] + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[15] + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[16] + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[17] + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[18] + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (d ^ (b & (c ^ d))) + e + w.w[19] + 0x5a827999; e = d; d = c; c = roll(b, 30); b = a; a = temp;

	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[20] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[21] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[22] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[23] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[24] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[25] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[26] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[27] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[28] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[29] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[30] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[31] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[32] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[33] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[34] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[35] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[36] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[37] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[38] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[39] + 0x6ed9eba1; e = d; d = c; c = roll(b, 30); b = a; a = temp;

	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[40] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[41] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[42] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[43] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[44] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[45] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[46] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[47] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[48] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[49] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[50] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[51] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[52] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[53] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[54] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[55] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[56] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[57] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[58] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + w.w[59] + 0x8f1bbcdc; e = d; d = c; c = roll(b, 30); b = a; a = temp;

	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[60] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[61] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[62] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[63] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[64] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[65] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[66] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[67] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[68] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[69] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[70] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[71] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[72] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[73] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[74] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[75] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[76] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[77] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[78] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;
	temp = roll(a, 5) + (b ^ c ^ d) + e + w.w[79] + 0xca62c1d6; e = d; d = c; c = roll(b, 30); b = a; a = temp;

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
