#include "common.h"

#define CAFILE "rootcert.pem"
#define CADIR NULL
#define CERTFILE "client.pem"

SSL_CTX *setup_client_ctx(void) {
	SSL_CTX *ctx;

//	ctx = SSL_CTX_new(SSLv23_method());
	ctx = SSL_CTX_new(TLSv1_2_method());
	if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
		int_error("Error loading CA file and/or directory");
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
		int_error("Error loading default CA file and/or directory");
	if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
		int_error("Error loading certificate from file");
	if (SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
		int_error("Error loading private key from file");
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	SSL_CTX_set_verify_depth(ctx, 4);
	return ctx;
}

int do_client_loop(SSL *ssl) {
	int err, nwritten;
	message_t message;

	// 날짜 정보 생성
	time_t today;
	struct tm *info;
	struct timeval time_now;
	gettimeofday(&time_now, NULL);
	info = localtime(&time_now.tv_sec);

	// start JSON 데이터 생성
	json_t *json = json_object();


	json_t *partner = json_object();
	json_object_set(partner, "comId", json_string("uberple"));
	json_object_set(partner, "srvId", json_string("SNEK"));

	json_t *commonHeader = json_object();
	json_object_set(commonHeader, "reqIdPlatform",
			json_string("P0001-ABC-0001"));
	json_object_set(commonHeader, "reqIdConsumer",
			json_string("Uberple-00001"));
	json_object_set(commonHeader, "certDn",
			json_string(
					"cn=김흥재_0000033643,ou=KOSCOM,ou=LicensedCA,o=SignKorea,c=KR"));
	json_object_set(commonHeader, "ci",
			json_string(
					"834f889833602f174a706138f19778a2dc6eee0f834f889833602f174a706138f19778a2dc6eee0feee0f22"));

	json_t *devInfo = json_object();
	json_object_set(devInfo, "ipAddr", json_string("192168001010"));
	json_object_set(devInfo, "macAddr", json_string("7054D27EE247"));

	json_t *accInfo = json_object();
	json_object_set(accInfo, "realAccNo", json_string("001-01-992323232"));
	json_object_set(accInfo, "vtAccNp", json_string("123214985324234"));

	json_t *queryType = json_object();
	json_object_set(queryType, "assetType", json_string("ALL"));
	json_object_set(queryType, "rspType", json_string("RAT"));

	json_t *portfolioRequest = json_object();
	json_object_set(json, "portfolioRequest", portfolioRequest);
	json_object_set(portfolioRequest, "partner", partner);
	json_object_set(portfolioRequest, "commonHeader", commonHeader);
	json_object_set(portfolioRequest, "devInfo", devInfo);

	json_t *body = json_object();
	json_object_set(portfolioRequest, "body", body);
	json_object_set(body, "accInfo", accInfo);
	json_object_set(body, "queryType", queryType);
	// end JSON 데이터 생성

	// JSON 데이터를 메시지 정보에 저장
	message.json_body = json_dumps(json, 0);

	// 메시지의 헤더 정보 생성
	strcpy(message.header.api_version, "1.00");
	sprintf(message.header.msg_length, "%d", strlen(message.json_body));
	strcpy(message.header.msg_type, "VTACCPORT");
	sprintf(message.header.seq_no, "%012d", 1);
	strftime(message.header.send_time, sizeof(message.header.send_time),
			"%Y%m%d%H%M%S", info);
	sprintf(message.header.send_time, "%s%02d", message.header.send_time,
			time_now.tv_usec / 1000);
	strncpy(message.header.transaction, "REQ_", 4);
	strncpy(message.header.compression, "N",
			sizeof(message.header.compression));
	strncpy(message.header.encrypt, "N", sizeof(message.header.encrypt));
	memset(message.header.dummy, 0x00, sizeof(message.header.dummy));

	for (;;) {
		// 메시지의 헤더 정보 송신
		for (nwritten = 0; nwritten < sizeof(message.header); nwritten += err) {
			err = SSL_write(ssl, &(message.header) + nwritten,
					sizeof(message.header) - nwritten);
			if (err <= 0) {
				printf("error : %d\n", SSL_get_error(ssl, err));
				return 0;
			}
		}
		// 메시지의 JSON 데이터 송신
		for (nwritten = 0; nwritten < strlen(message.json_body); nwritten +=
				err) {
			err = SSL_write(ssl, message.json_body + nwritten,
					strlen(message.json_body) - nwritten);
			if (err <= 0) {
				printf("error : %d\n", SSL_get_error(ssl, err));
				return 0;
			}
		}

		// 메시지 데이터 리셋
		memset(&message, 0x00, sizeof(message));

		int r;
		int offset = 0;
		int length = sizeof(message.header);
		// 메시지의 헤더 정보 수신
		while (length > offset) {
			r = SSL_read(ssl, &(message.header) + offset, length - offset);
			switch (SSL_get_error(ssl, r)) {
			case SSL_ERROR_NONE:
				offset += r;
				break;
			case SSL_ERROR_WANT_READ:
				continue;
			case SSL_ERROR_ZERO_RETURN:
				break;
			case SSL_ERROR_SYSCALL:
				fprintf(stderr, "SSL Error: Premature close\n");
				goto end;
				break;
			default:
				printf("SSL read problem");
				goto end;
				break;
			}
		}

		// 데이터 확인
		if (offset == length) {
			// 메시지의 헤더 정보 표시
			fwrite(&(message.header), 1, offset, stdout);
			length = atoi(message.header.msg_length);
			// 메지시의 JSON 데이터 메모리 확보
			message.json_body = (char*) malloc(length);
			offset = 0;
			// 메시지의 JSON 데이터 수신
			while (length > offset) {
				r = SSL_read(ssl, message.json_body + offset, length - offset);
				switch (SSL_get_error(ssl, r)) {
				case SSL_ERROR_NONE:
					offset += r;
					break;
				case SSL_ERROR_WANT_READ:
					continue;
				case SSL_ERROR_ZERO_RETURN:
					break;
				case SSL_ERROR_SYSCALL:
					fprintf(stderr, "SSL Error: Premature close\n");
					goto end;
					break;
				default:
					printf("SSL read problem");
					goto end;
					break;
				}
			}
			// 메시지의 JSON 데이터 표시
			fwrite(message.json_body, 1, offset, stdout);
			//goto end;
		}
		fflush(stdout);
	}
	end: return 1;
}

int main(int argc, char *argv[]) {
	BIO *conn;
	SSL *ssl;
	SSL_CTX *ctx;
	long err;

	init_OpenSSL();
	seed_prng();

	ctx = setup_client_ctx();

	conn = BIO_new_connect(SERVER ":" PORT);
	if (!conn)
		int_error("Error creating connection BIO");

	if (BIO_do_connect(conn) <= 0)
		int_error("Error connecting to remote machine");

	// SSL 객체 생성
	ssl = SSL_new(ctx);
	// read/write를 위한 BIO 객체 설정
	SSL_set_bio(ssl, conn, conn);

	// 서버로 SSL/TLS 연결
	if (SSL_connect(ssl) <= 0)
		int_error("Error connecting SSL object");
	// SSL/TLS 연결 후, 인증서 확인
	if ((err = post_connection_check(ssl, SERVER)) != X509_V_OK) {
		fprintf(stderr, "-Error: peer certificate: %s\n",
				X509_verify_cert_error_string(err));
		int_error("Error checking SSL object after connection");
	}
	fprintf(stderr, "SSL Connection opened\n");
	if (do_client_loop(ssl))
		SSL_shutdown(ssl);
	else
		SSL_clear(ssl);
	fprintf(stderr, "SSL Connection closed\n");

	SSL_free(ssl);
	SSL_CTX_free(ctx);
	return 0;
}
