#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "firewall_log.h"

int read_logs_from_file(const char *filename, char logs[][512]) {
	    FILE *fp = fopen(filename, "r");
	    if (!fp) return 0;
	    
	    int count = 0;
	    while (fgets(logs[count], 512, fp) && count < MAX_LOGS) {
		    logs[count][strcspn(logs[count], "\n")] = '\0';
		    count++;

	    }

	    fclose(fp);
	    return count;
}
int parse_log(const char *line, firewall_log_t *log) {
	return sscanf(line,
	     "{'event.start': '%79[^']','destination.ip': '%79[^']','destination.host': '%79[^']',"
	     "'source.ip': '%79[^']','source.host': '%79[^']','client.bytes': '%d','server.bytes': '%d',"
	     "'http.request.time': '%d','http.response.time': '%d','user.name': '%79[^']',"
	     "'event.outcome': '%79[^']','event.type': '%79[^']','event.category': '%79[^']',"
	     "'event.action': '%79[^']'}",
	     log->event_start, log->destination_ip, log->destination_host,
	     log->source_ip, log->source_host, &log->client_bytes, &log->server_bytes,
	     &log->http_request_time, &log->http_response_time, log->user_name,
	     log->event_outcome, log->event_type, log->event_category, log->event_action);
}

void print_log(const firewall_log_t *log) {
	printf("event.start = %s\n", log->event_start);
	printf("destination.ip = %s, destination.host = %s\n", log->destination_ip, log->destination_host);
	printf("source.ip = %s, source.host = %s\n", log->source_ip, log->source_host);
	printf("client.bytes = %d, server.bytes = %d\n", log->client_bytes, log->server_bytes);
	printf("http.request.time = %d, http.response.time = %d\n", log->http_request_time, log->http_response_time);
	printf("user.name = %s\n", log->user_name);
	printf("event.outcome = %s, event.type = %s, event.category = %s, event.action = %s\n",
	        log->event_outcome, log->event_type, log->event_category, log->event_action);
}		   

