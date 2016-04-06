#include "common.h"
#include <ctype.h>
#include <sys/time.h>
#include <fcntl.h>

int connectlist[5];
fd_set socks;
int highsock;

#define CAFILE "rootcert.pem"
#define CADIR NULL
#define CERTFILE "server.pem"

typedef enum {
	HEADER,
	JSON
} READ_STATE;

SSL_CTX *setup_server_ctx(void)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(SSLv23_method());
	if (SSL_CTX_load_verify_locations(ctx, CAFILE, CADIR) != 1)
		int_error("Error loading CA file and/or directory");
	if (SSL_CTX_set_default_verify_paths(ctx) != 1)
		int_error("Error loading default CA file and/or directory");
	if (SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
		int_error("Error loading certificate from file");
	if (SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
		int_error("Error loading private key from file");
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
			verify_callback);
	SSL_CTX_set_verify_depth(ctx, 4);
	return ctx;
}

void setnonblocking(int sock)
{
	int opts;

	opts = fcntl(sock, F_GETFL);
	if (opts < 0) {
		perror("fcntl(F_GETFL)");
		exit(EXIT_FAILURE);
	}
	opts = (opts | O_NONBLOCK);
	if (fcntl(sock, F_SETFL, opts) < 0) {
		perror("fcntl(F_SETFL)");
		exit(EXIT_FAILURE);
	}
	return;
}

void read_write(SSL_CTX *ctx, int sock)
{
	int width;
	int r, c2sl = 0, c2s_offset = 0;
	int read_blocked_on_write = 0, write_blocked_on_read = 0, read_blocked = 0;
	fd_set readfds, writefds;
	int shutdown_wait = 0;
	char c2s[BUFSIZZ], s2c[BUFSIZZ];
	message_t message;
	int ofcmode;
	SSL *ssl = NULL;

	width = sock + 1;

	while (1) {
		READ_STATE state = HEADER;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		FD_SET(sock, &readfds);

		if (!write_blocked_on_read) {
			if (c2sl || read_blocked_on_write) {
				FD_SET(sock, &writefds);
			} else {
				FD_SET(sock, &readfds);
			}
		}

		r = select(width, &readfds, &writefds, 0, 0);
		if (r == 0) {
			continue;
		}

		if ((FD_ISSET(sock, &readfds) && !write_blocked_on_read)
				|| (read_blocked_on_write && FD_ISSET(sock, &writefds))) {
			int s;
			/*
			 * SSL 연결 과정
			 * 1. 연결 accept
			 * 2. SSL_new로 ssl 객체 생성
			 * 3. SSL_set_fd 로 SSL/TLS 연결에 사용할 소켓 설정
			 * 4. SSL_accept 로 SSL/TLS 연결 initiation
			 */
			if ((s = accept(sock, 0, 0)) < 0) {
				printf("Problem accepting\n");
				goto end;
			}

			if ((ssl = SSL_new(ctx)) == NULL) {
				printf("Problem SSL_new\n");
				goto end;
			}
			if (SSL_set_fd(ssl, s) <= 0) {
				printf("Problem SSL_set_fd\n");
				goto end;
			}

			if ((r = SSL_accept(ssl) <= 0)) {
				int err = SSL_get_error(ssl, r);
				printf("Problem SSL accepting, %d\n", err);
				goto end;
			}
			do {
				read_blocked_on_write = 0;
				read_blocked = 0;

				switch(state) {
				case HEADER:
					r = SSL_read(ssl, &(message.header), sizeof(message.header));
					break;
				case JSON:
					r = SSL_read(ssl, message.json_body, atoi(message.header.msg_length));
					break;
				default:
					goto end;
					break;
				}

				int err = SSL_get_error(ssl, r);

				// printf("error : %d, %d, %d\n", err, state, atoi(message.header.msg_length));

				// SSL error 처리
				switch (err) {
					case SSL_ERROR_NONE:
						if(state == HEADER && r == sizeof(message.header)) {
							// 화면에 메시지 헤더 정보 표시
							fwrite(&(message.header), 1, r, stdout);
							message.json_body = (char*)malloc(atoi(message.header.msg_length));
							state = JSON;
						} else if(state == JSON && r == atoi(message.header.msg_length)) {
							// 화면에 JSON 데이터 표시
							fwrite(message.json_body, 1, r, stdout);

							// 클라이언트로 데이터를 전송하기 위한 플래그 설정
							write_blocked_on_read = 1;
							read_blocked = 1;

							state = HEADER;
						}
						break;
					case SSL_ERROR_ZERO_RETURN:
						if (!shutdown_wait)
							SSL_shutdown(ssl);
						goto end;
						break;
					case SSL_ERROR_WANT_READ:
						read_blocked = 1;
						break;
					case SSL_ERROR_WANT_WRITE:
						read_blocked_on_write = 1;
						break;
					default:
						printf("SSL read problem\n");
						goto end;
				}
				fflush(stdout);
			} while (!read_blocked); // SSL_pending(ssl) && !read_blocked);
		}

		// 메시지 초기화
		memset(&message, 0x00, sizeof(message));
		c2sl = sizeof(message.header);
		c2s_offset = 0;

		// 메시지 전송
		if ((FD_ISSET(sock, &writefds) && c2sl)
				|| (write_blocked_on_read && FD_ISSET(sock, &readfds))) {
			write_blocked_on_read = 0;

			// 날짜 정보 생성
			time_t today;
			struct tm *info;
			struct timeval time_now;
			gettimeofday(&time_now, NULL);
			info = localtime(&time_now.tv_sec);

			// 메시지의 헤더 정보 생성
			strcpy(message.header.api_version, "1.00");
			strcpy(message.header.msg_type, "VTACCPORT");
			sprintf(message.header.seq_no, "%012d", 1);
			strftime(message.header.send_time, sizeof(message.header.send_time),
					"%Y%m%d%H%M%S", info);
			sprintf(message.header.send_time, "%s%02d", message.header.send_time,
					time_now.tv_usec / 1000);
			strncpy(message.header.transaction, "RSP_", 4);
			strncpy(message.header.compression, "N",
					sizeof(message.header.compression));
			strncpy(message.header.encrypt, "N", sizeof(message.header.encrypt));
			memset(message.header.dummy, 0x00, sizeof(message.header.dummy));

			// 클라이언트로 보낼 JSON 데이터 생성
			json_t *json = json_object();
			json_t *portfolioRequest = json_object();

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

			json_t *body = json_object();

			json_t *accInfo = json_object();
			json_object_set(accInfo, "realAccNo", json_string("001-01-992323232"));
			json_object_set(accInfo, "vtAccNp", json_string("123214985324234"));

			json_t *queryType = json_object();
			json_object_set(queryType, "assetType", json_string("ALL"));
			json_object_set(queryType, "rspType", json_string("RAT"));

			json_t *portfolio = json_object();
			json_t *cash = json_object();
			json_object_set(cash, "amt", json_integer(3543543));
			json_object_set(portfolio, "cash", cash);

			json_t *equityList = json_array();
			json_t *equity = json_object();
			json_object_set(equity, "isinCode", json_string("testCode"));
			json_object_set(equity, "qty", json_integer(5));
			json_object_set(equity, "earningRate", json_integer(9));

			json_array_append(equityList, equity);
			json_array_append(equityList, equity);

			json_object_set(portfolio, "equityList", equityList);

			json_t *fundList = json_array();
			json_t *fund = json_object();
			json_object_set(fund, "fundCode", json_string("fundCode"));
			json_object_set(fund, "fundName", json_string("fundName"));
			json_object_set(fund, "qty", json_integer(56));
			json_object_set(fund, "earningRate", json_integer(6));
			json_object_set(fund, "maturity", json_string("20160405"));

			json_array_append(fundList, fund);
			json_array_append(fundList, fund);

			json_object_set(portfolio, "fundList", fundList);

			json_t *etcList = json_array();
			json_t *etc = json_object();
			json_object_set(etc, "assetType", json_string("BOND"));
			json_object_set(etc, "assetName", json_string("BOND Test"));
			json_object_set(etc, "qty", json_integer(57));
			json_object_set(etc, "earningRate", json_integer(7));

			json_array_append(etcList, etc);
			json_array_append(etcList, etc);

			json_object_set(portfolio, "etcList", etcList);

			json_t *resp = json_object();
			json_object_set(resp, "resCode", json_string("200"));
			json_object_set(resp, "respMsg", json_string("OK"));

			json_object_set(json, "resp", resp);

			json_object_set(json, "portfolioRequest", portfolioRequest);
			json_object_set(json, "portfolio", portfolio);
			json_object_set(portfolioRequest, "partner", partner);
			json_object_set(portfolioRequest, "commonHeader", commonHeader);
			json_object_set(portfolioRequest, "devInfo", devInfo);
			json_object_set(portfolioRequest, "body", body);
			json_object_set(body, "accInfo", accInfo);
			json_object_set(body, "queryType", queryType);

			// 메시지에 JSON 데이터 저장
			message.json_body = json_dumps(json, 0);

			// 메시지의 헤더 정보에 보낼 JSON 데이터 크기 설정
			sprintf(message.header.msg_length, "%d", strlen(message.json_body));

			// 클라이언트로 메시지 헤더 전송
			while(c2sl > 0) {
				r = SSL_write(ssl, &(message.header) + c2s_offset, c2sl);

				switch (SSL_get_error(ssl, r)) {
					case SSL_ERROR_NONE:
						c2sl -= r;
						c2s_offset += r;
						break;
					case SSL_ERROR_WANT_WRITE:
						break;
					case SSL_ERROR_WANT_READ:
						write_blocked_on_read = 1;
						break;
					default:
						printf("SSL write problem");
						goto end;
				}
			}

			c2s_offset = 0;
			c2sl = strlen(message.json_body);
			// 클라이언트로 JSON 데이터 전송
			while(c2sl > 0) {
				r = SSL_write(ssl, message.json_body + c2s_offset, c2sl);

				switch (SSL_get_error(ssl, r)) {
					case SSL_ERROR_NONE:
						c2sl -= r;
						c2s_offset += r;
						break;
					case SSL_ERROR_WANT_WRITE:
						break;
					case SSL_ERROR_WANT_READ:
						write_blocked_on_read = 1;
						break;
					default:
						printf("SSL write problem");
						goto end;
				}
			}
			//goto end;
		}
	}

	end:
	if(ssl != NULL) {
		SSL_free(ssl);
	}
	if(message.json_body != NULL) {
		free(message.json_body);
	}
	return;
}

int main(int argc, char *argv[])
{
	SSL_CTX *ctx;

	init_OpenSSL();
	seed_prng();

	ctx = setup_server_ctx();

	// 서버의 포트 번호
	int port = 16001;
	struct sockaddr_in server_address;
	int reuse_addr = 1;
	struct timeval timeout;
	int readsocks;
	int sock;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr));

	memset((char *) &server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;
	server_address.sin_addr.s_addr = htonl(INADDR_ANY);
	server_address.sin_port = htons(port);
	if (bind(sock, (struct sockaddr *) &server_address, sizeof(server_address))
			< 0) {
		perror("bind");
		close(sock);
		exit(EXIT_FAILURE);
	}

	listen(sock, 5);

	memset((char *) &connectlist, 0, sizeof(connectlist));
	while(1) {
		highsock = sock;

		read_write(ctx, sock);
	}
}
