#ifndef FIREWALL_LOG_H
#define FIREWALL_LOG_H

#define STR_SIZE 80
#define MAX_LOGS 100

typedef struct {
	    char event_start[STR_SIZE];
	    char destination_ip[STR_SIZE];
	    char destination_host[STR_SIZE];
            char source_ip[STR_SIZE];
	    char source_host[STR_SIZE];
	    int client_bytes;
	    int server_bytes;
	    int http_request_time;
	    int http_response_time;
	    char user_name[STR_SIZE];
	    char event_outcome[STR_SIZE];
	    char event_type[STR_SIZE];
	    char event_category[STR_SIZE];
	    char event_action[STR_SIZE];
} firewall_log_t;

int read_logs_from_file(const char *filename, char logs[][512]);
int parse_log(const char *line, firewall_log_t *log);
void print_log(const firewall_log_t *log);

#endif
						 
							   
