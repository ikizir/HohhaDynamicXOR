#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int hohha_dbg_level;

uint32_t xorEncrypt(uint8_t *K,
		    uint8_t *Salt,
		    uint32_t KeyCheckSum,
		    size_t InOutDataLen,
		    uint8_t *InOutBuf);

uint32_t xorDecrypt(uint8_t *K,
		    uint8_t *Salt,
		    uint32_t KeyCheckSum,
		    size_t InOutDataLen,
		    uint8_t *InOutBuf);

char *Base64Encode(const char* input,
		   uint32_t inputlen);

char *Base64DecodeLen(const char* input,
		      uint32_t *outputLen);

unsigned int digital_crc32(uint8_t *buf, size_t len);

int main(int argc, char **argv)
{
	int rc, errflg = 0;

	int op = 0;
	char *arg_K = NULL;
	char *arg_S = NULL;
	char *arg_M = NULL;
	char *arg_m = NULL;

	uint8_t *raw_K;
	uint32_t raw_K_len;
	uint32_t raw_K_crc;

	uint8_t *raw_S;

	uint8_t *raw_m;
	uint32_t raw_m_len;

	char *out_m;
	uint32_t out_m_len;

	opterr = 1;
	while ((rc = getopt(argc, argv, "DdeK:S:M:m:v")) != -1) {
		switch (rc) {

		case 'D': /* decrypt (plain) */
		case 'd': /* decrypt (base64) */
		case 'e': /* encrypt (base64) */
			op = rc;
			break;

		case 'K': /* key: base64 (hohha format) */
			arg_K = optarg;
			break;

		case 'S': /* override salt: eight numeric */
			arg_S = optarg;
			break;

		case 'M': /* message: plain */
			arg_M = optarg;
			arg_m = NULL;
			break;

		case 'm': /* message: base64 */
			arg_m = optarg;
			arg_M = NULL;
			break;

		case 'v': /* increase verbosity */
			++hohha_dbg_level;
			break;

		case ':':
		case '?':
			++errflg;
		}
	}

	if (!op) {
		fprintf(stderr, "missing one of -c or -d or -e\n");
		++errflg;
	}

	if (!arg_K) {
		fprintf(stderr, "missing -K for key\n");
		++errflg;
	}

	if (!arg_M && !arg_m) {
		fprintf(stderr, "missing -M or -m for message\n");
		++errflg;
	}

	if (optind != argc) {
		fprintf(stderr, "error: trailing arguments... %s\n", argv[optind]);
		++errflg;
	}

	if (errflg) {
		fprintf(stderr,
			"usage: %s <method> <key> <message> [-v]\n"
			"\n"
			"  method: from the following options\n"
			"    -D\n"
			"      Decrypt the cyphertext message (plain)\n"
			"    -d\n"
			"      Decrypt the cyphertext message (base64)\n"
			"    -e\n"
			"      Encrypt the plaintext message (base64)\n"
			"\n"
			"  key: from the following options\n"
			"    -K <key>\n"
			"      Hohha key format (base64)\n"
			"    -S <salt>\n"
			"      Override key salt (eight numeric)\n"
			"\n"
			"  message: from the following options\n"
			"    -M <msg>\n"
			"      Message (plain)\n"
			"    -m <msg>\n"
			"      Message (base64)\n"
			"\n"
			"  -v\n"
			"      Increase debug verbosity (may be repeated)\n"
			"\n",
			argv[0]);
		exit(2);
	}

	if (hohha_dbg_level > 0) {
		int v;

		fprintf(stderr, "command: %s -%c", argv[0], op);

		for (v = 0; v < hohha_dbg_level; ++v)
			fprintf(stderr, " -v");

		if (arg_K)
			fprintf(stderr, " -K '%s'", arg_K);

		if (arg_S)
			fprintf(stderr, " -S '%s'", arg_S);

		if (arg_M)
			fprintf(stderr, " -M '%s'", arg_M);

		if (arg_m)
			fprintf(stderr, " -m '%s'", arg_m);

		fprintf(stderr, "\n");
	}

	if (arg_K) {
		raw_K = Base64DecodeLen(arg_K, &raw_K_len);
	}

	if (arg_S) {
		raw_S = malloc(8);

		rc = sscanf(arg_S, "%hhu %hhu %hhu %hhu %hhu %hhu %hhu %hhu\n",
		       &raw_S[0], &raw_S[1], &raw_S[2], &raw_S[3],
		       &raw_S[4], &raw_S[5], &raw_S[6], &raw_S[7]);
		if (rc != 8) {
			fprintf(stderr, "invalid -S '%s'\n", arg_S);
			exit(1);
		}
	} else {
		raw_S = raw_K + 3;
	}

	if (arg_M) {
		raw_m = (void *)arg_M;
		raw_m_len = strlen(arg_M);
	}

	if (arg_m) {
		raw_m = Base64DecodeLen(arg_m, &raw_m_len);
	}

	raw_K_crc = digital_crc32(raw_K + 11, *(uint16_t *)(raw_K + 1));

	switch (op) {
	case 'D':
	case 'd':
		xorDecrypt(raw_K, raw_S, raw_K_crc,
			   raw_m_len, raw_m);
		break;

	case 'e':
		xorEncrypt(raw_K, raw_S, raw_K_crc,
			   raw_m_len, raw_m);
	}

	switch (op) {
	case 'D':
		out_m = (void *)raw_m;
		out_m_len = raw_m_len;
		break;

	case 'd':
	case 'e':
		out_m = Base64Encode(raw_m, raw_m_len);
		out_m_len = strlen(out_m);
	}

	fwrite(out_m, 1, out_m_len, stdout);

	if (isatty(1))
		fputc('\n', stdout);

	return 0;
}
