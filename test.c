#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

void sha1_ni_transform(uint32_t *digest, const void *data);

struct digest {
	uint32_t h0, h1, h2, h3, h4;
};

void init(struct digest *d)
{
	d->h0 = 0x67452301;
	d->h1 = 0xefcdab89;
	d->h2 = 0x98badcfe;
	d->h3 = 0x10325476;
	d->h4 = 0xc3d2e1f0;
}

void my_sha1(const unsigned char *data, unsigned int size, unsigned char *out)
{
	struct digest d;
	init(&d);

	uint8_t chunk[64];
	int di = 0;

	while (size - di >= 64) {
		// todo use chunk only in last chunk, otherwise use data directly
		memcpy(chunk, data + di, 64);
		sha1_ni_transform((uint32_t *)&d, chunk);
		di += 64;
	}

	memcpy(chunk, data + di, size - di);
	chunk[size - di] = 0x80;
	memset(chunk + (size - di) + 1, 0, 64 - (size - di) - 1 - 4);
	chunk[60] = size >> 21;
	chunk[61] = size >> 13;
	chunk[62] = size >> 5;
	chunk[63] = size << 3;

	sha1_ni_transform((uint32_t *)&d, chunk);

	out[0] = d.h0 >> 24;
	out[1] = d.h0 >> 16;
	out[2] = d.h0 >> 8;
	out[3] = d.h0;
	out[4] = d.h1 >> 24;
	out[5] = d.h1 >> 16;
	out[6] = d.h1 >> 8;
	out[7] = d.h1;
	out[8] = d.h2 >> 24;
	out[9] = d.h2 >> 16;
	out[10] = d.h2 >> 8;
	out[11] = d.h2;
	out[12] = d.h3 >> 24;
	out[13] = d.h3 >> 16;
	out[14] = d.h3 >> 8;
	out[15] = d.h3;
	out[16] = d.h4 >> 24;
	out[17] = d.h4 >> 16;
	out[18] = d.h4 >> 8;
	out[19] = d.h4;
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
