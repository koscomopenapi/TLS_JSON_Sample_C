typedef struct {
	char api_version[4];
	char msg_length[6];
	char transaction[4];
	char msg_type[12];
	char seq_no[12];
	char send_time[16];
	char encrypt[1];
	char compression[1];
	char dummy[16];
} header_t;

typedef struct {
	header_t header;
	char *json_body;
} message_t;
