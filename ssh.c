/**
 * Basic ssh functionality:
 * 1. Basic ssh server
 * 2. Basic ssh client
 * 3. Support for remote forwarded tunnels
 */
 
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
		ssh_bind sshbind = ssh_bind_new();
		ssh_session session = ssh_new();
		
		//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_DSAKEY,
		//					 "/etc/ssh/ssh_host_dsa_key");
		ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY,
							 "/etc/ssh/ssh_host_rsa_key");
		// only for non-standard port?
		//ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, )

		printf("Calling ssh_bind_listen...\n");
		if (ssh_bind_listen(sshbind) < 0) {
			printf("Error listening to socket: %s\n", ssh_get_error(sshbind));
			return -1;
		}
		printf("Calling ssh_bind_accept...\n");
		if (ssh_bind_accept(sshbind, session) == SSH_ERROR) { // return as soon as
															  // TCP handshake is done
			printf("Error accepting a connection: %s\n", ssh_get_error(sshbind));
			return -1;
		}

		if (ssh_handle_key_exchange(session)) {
			printf("ssh_handle_kez_exchange: %s:\n", ssh_get_error(session));
			return -1;
		}
/**
		int auth = 0;
		ssh_message message;
		ssh_channel chan = 0;
		do {
			message = ssh_message_get(session);
			if (!message)
				break;
			switch (ssh_message_type(message)) {
			case SSH_REQUEST_AUTH:
				switch (ssh_message_subtype(message)) {
				case SSH_AUTH_METHOD_PASSWORD:
					printf("User %s wants to authenticate with password %s\n",
						   ssh_message_auth_user(message),
						   ssh_message_auth_password(message));
					if (auth_password(ssh_message_auth_user(message),
									  ssh_message_auth_password(message))) {
						auth = 1;
						ssh_message_auth_reply_success(message, 0);
						break;				  
					}
					// not authenticated!
				case SSH_AUTH_METHOD_NONE:
				default:
					ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD); // ++
					ssh_message_reply_default(message);
					break;
				}
				break;
			default:
				ssh_message_reply_default(message);
			}
			ssh_message_free(message);
		} while (!auth);
		
		if (!auth) {
			printf("Auth error: %s\n", ssh_get_error(session));
			ssh_disconnect(session);
			return -1;
		}
		
		do {
			message = ssh_get_message(session);
			if (message) {
				switch (ssh_message_type(message)) {
				case SSH_REQUEST_CHANNEL_OPEN:
					if (ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
						chan = ssh_message_channel_request_open_reply_accept(message);
						break;
					}
				default:
					ssh_message_reply_default(message);
				}
			ssh_message_free();
			}
		} while (message && !chan);
		
		if (!chan) {
        	printf("error : %s\n", ssh_get_error(session));
        	ssh_finalize();
        	return 1;
		}
		
		do {
        	message = ssh_message_get(session);
        	if (message && ssh_message_type(message) == SSH_REQUEST_CHANNEL &&
			    ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL) {
//              if(!strcmp(ssh_message_channel_request_subsystem(message),"sftp")){
                sftp=1;
                ssh_message_channel_request_reply_success(message);
                break;
 //           	}
			}
		    if(!sftp){
		        ssh_message_reply_default(message);
			}
			ssh_message_free(message);
		} while (message && !sftp);

		if(!sftp){
        	printf("error : %s\n",ssh_get_error(session));
        	return 1;
   		}
    	
    	printf("it works !\n");
    	
    	int i = 0;
    	char buf[2048];
		do{
        	i = ssh_channel_read(chan, buf, 2048, 0);
        	if (i > 0) {
            	ssh_channel_write(chan, buf, i);
            	if ( write(1, buf, i) < 0) {
                	printf("error writing to buffer\n");
                	return -1;
 	           }
        	}
		} while (i > 0);
*/		
		ssh_disconnect(session);
		ssh_bind_free(sshbind);
		ssh_finalize();
		return 0;
}
