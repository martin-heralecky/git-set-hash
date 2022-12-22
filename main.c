#define _GNU_SOURCE

#include <git2.h>
#include <math.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char target[40];
int target_size;

char *commit_template;

int cpu_count;

_Atomic bool found = false;
_Atomic unsigned long long magic;

int parse_target(const char *arg)
{
	target_size = strlen(arg);

	if (target_size < 1 || target_size > 40) {
		fprintf(stderr, "error: length of target hash is not between 1 and 40 bytes\n");
		return -1;
	}

	for (int i = 0; i < target_size; ++i) {
		char c = arg[i];
		if (c >= '0' && c <= '9') {
			target[i] = c - '0';
		} else if (c >= 'A' && c <= 'F') {
			target[i] = c - 'A' + 10;
		} else if (c >= 'a' && c <= 'f') {
			target[i] = c - 'a' + 10;
		} else {
			fprintf(stderr, "error: invalid character in target hash: %c\n", c);
			return -1;
		}
	}

	return 0;
}

int get_cpu_count(int *count_out)
{
	cpu_set_t cs;

	if (sched_getaffinity(0, sizeof(cs), &cs) != 0) {
		return -1;
	}

	*count_out = CPU_COUNT(&cs);

	return 0;
}

void format_magic(unsigned long long m, char m_out[12], int *m_size_out)
{
	static const char *alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

	int out_i = 0;
	for (int i = 10; i >= 0; --i) {
		unsigned long long d = (unsigned long long)pow(62, i);
		int c = m / d;

		if (out_i > 0 || c > 0) {
			m_out[out_i] = alphabet[c];
			m -= c * d;
			++out_i;
		}
	}

	if (out_i == 0) {
		m_out[out_i] = alphabet[0];
		++out_i;
	}

	m_out[out_i] = '\0';

	*m_size_out = out_i;
}

bool is_target_hit(const unsigned char *hash)
{
	for (int i = 0; i < target_size; ++i) {
		if (i % 2 == 0) {
			if (target[i] != (hash[i/2] >> 4)) {
				return false;
			}
		} else {
			if (target[i] != (hash[i/2] & 0x0f)) {
				return false;
			}
		}
	}

	return true;
}

void *run(void *_n)
{
	unsigned long long n = (unsigned long long)_n;
	unsigned long long m = n;

	char m_str[12];
	int m_size;
	int m_last_size = -1;

	char *obj = NULL;
	int obj_size = 0;
	char *obj_m = NULL;

	unsigned char hash[20];

	do {
		if (found) {
			break;
		}

		format_magic(m, m_str, &m_size);

		if (m_size > m_last_size) {
			free(obj);

			int commit_template_size = strlen(commit_template);
			int commit_size = commit_template_size + m_size + 1;

			char obj_header[18];
			sprintf(obj_header, "commit %u", (unsigned int)commit_size);
			int obj_header_size = strlen(obj_header);

			obj_size = obj_header_size + 1 + commit_size;
			obj = malloc(obj_size);

			strcpy(obj, obj_header);
			strcpy(obj + obj_header_size + 1, commit_template);
			obj[obj_header_size + 1 + commit_template_size + m_size] = '\n';

			obj_m = obj + obj_header_size + 1 + commit_template_size;
		}

		m_last_size = m_size;

		memcpy(obj_m, m_str, m_size);

		SHA1((unsigned char *)obj, obj_size, hash);

		if (is_target_hit(hash)) {
			magic = m;
			found = true;
		}

		m += cpu_count;
	} while (m > n);

	free(obj);

	return NULL;
}

int compute(const char *commit_raw, char **trailer_out)
{
	commit_template = malloc(strlen(commit_raw) + 9);
	sprintf(commit_template, "%s\nmagic: ", commit_raw);

	if (get_cpu_count(&cpu_count) != 0) {
		fprintf(stderr, "error: could not get CPU count\n");
		return -1;
	}

	printf("computing hashes on %d threads...\n", cpu_count);

	pthread_t *threads = calloc(cpu_count, sizeof(pthread_t));
	for (int i = 0; i < cpu_count; ++i) {
		if (pthread_create(&threads[i], NULL, run, (void *)(unsigned long long)i) != 0) {
			fprintf(stderr, "error: could not create thread\n");
			return -1;
		}
	}

	for (int i = 0; i < cpu_count; ++i) {
		if (pthread_join(threads[i], NULL) != 0) {
			fprintf(stderr, "error: could not join thread\n");
			return -1;
		}
	}

	free(threads);
	free(commit_template);

	if (!found) {
		fprintf(stderr, "error: magic not found\n");
		return -1;
	}

	char magic_str[12];
	int magic_str_size;
	format_magic(magic, magic_str, &magic_str_size);

	printf("found magic: %s\n", magic_str);

	*trailer_out = malloc(8 + magic_str_size + 2);
	strcpy(*trailer_out, "\nmagic: ");
	strcpy(*trailer_out + 8, magic_str);
	strcpy(*trailer_out + 8 + magic_str_size, "\n");

	return 0;
}

int main(int argc, char **argv)
{
	if (argc != 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
		fprintf(stderr, "usage\n"); // TODO
		return 1;
	}

	if (parse_target(argv[1]) != 0) {
		fprintf(stderr, "error: could not parse target hash\n");
		return 1;
	}

	git_libgit2_init();

	git_repository *repo;
	if (git_repository_open(&repo, ".") != 0) {
		fprintf(stderr, "error: could not open git repository\n");
		return 1;
	}

	git_oid commit_id;
	if (git_reference_name_to_id(&commit_id, repo, "HEAD") != 0) {
		fprintf(stderr, "error: could not find reference HEAD\n");
		return 1;
	}

	git_commit *commit;
	if (git_commit_lookup(&commit, repo, &commit_id) != 0) {
		fprintf(stderr, "error: could not find commit for HEAD\n");
		return 1;
	}

	git_odb *odb;
	if (git_repository_odb(&odb, repo) != 0) {
		fprintf(stderr, "error: could not get repository ODB\n");
		return 1;
	}

	git_odb_object *commit_odb_obj;
	if (git_odb_read(&commit_odb_obj, odb, &commit_id) != 0) {
		fprintf(stderr, "error: could not read commit object from ODB\n");
		return 1;
	}

	const char *commit_raw = git_odb_object_data(commit_odb_obj);

	char *trailer;
	if (compute(commit_raw, &trailer) != 0) {
		return 1;
	}

	git_odb_object_free(commit_odb_obj);
	git_odb_free(odb);

	const char *msg = git_commit_message_raw(commit);
	int msg_len = strlen(msg);

	char *new_msg = malloc(msg_len + strlen(trailer) + 1);
	strcpy(new_msg, msg);
	strcpy(new_msg + msg_len, trailer);

	free(trailer);

	if (git_commit_amend(&commit_id, commit, "HEAD", NULL, NULL, NULL, new_msg, NULL) != 0) {
		fprintf(stderr, "error: could not amend commit\n");
		return 1;
	}

	free(new_msg);

	char commit_hash[40];
	if (git_oid_fmt(commit_hash, &commit_id) != 0) {
		return 1;
	}

	printf("[%.40s] %s\n", commit_hash, git_commit_summary(commit));

	git_commit_free(commit);
	git_repository_free(repo);

	return 0;
}
