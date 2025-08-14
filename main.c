#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "firewall_log.h"

int main(int argc, char *argv[]){
	if (argc != 2){
		fprintf(stderr, "Usage: %s <logfile>\n", argv[0]);
		return 1;
	}

	char lines[MAX_LOGS][512];
	firewall_log_t logs[MAX_LOGS];

	int count = read_logs_from_file(argv[1], lines);
	if (count ==0){
		fprintf(stderr, "Error reading file or file is empty.\n");
		return 1;
	}

	for (int i = 0; i < count; i++) {
		if (parse_log(lines[i], &logs[i]) != 14){
			fprintf(stderr, "Error parsing line %d\n", i + 1);
			return 1;
		}
	}

	printf("First log parsed:\n");
	print_log(&logs[0]);

	for (int i = 0; i < count; i++) {
	    if (strcmp(logs[i].source_ip, "10.189.90.64") == 0 &&
		strcmp(logs[i].event_outcome, "blocked") == 0 &&
		strcmp(logs[i].event_category, "spyware") == 0 &&
		logs[i].server_bytes > 4200) {

		printf("\nMatching log found at index %d:\n", i);
		print_log(&logs[i]);
	}
    }
    return 0;
}
