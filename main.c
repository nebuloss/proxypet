#include <stdio.h>
#include <stdlib.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <pthread.h>
#include <signal.h>

typedef struct{
    ssh_session client_session,server_session;
    ssh_channel client_channel,server_channel;
    ssh_channel_callbacks client_channel_callbacks,server_channel_callbacks;
}proxy_session;

//more convenient way to perform explicit cast
#define PROXY_SESSION(ps) ((proxy_session*)ps)

proxy_session* newProxySession(){
    proxy_session* ps=malloc(sizeof(proxy_session));
    *ps=(proxy_session){
        .client_session=ssh_new(),
        .server_session=ssh_new(),
        .client_channel=NULL,
        .server_channel=NULL,
        .client_channel_callbacks=NULL,
        .server_channel_callbacks=NULL
    };
    return ps;
}

void freeChannel(ssh_channel channel){
    if (!channel) return;

    if (ssh_channel_is_open(channel)){
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
    }
    ssh_channel_free(channel);
}

void freeProxySession(proxy_session* ps){
    free(ps->client_channel_callbacks);
    free(ps->server_channel_callbacks);

    freeChannel(ps->client_channel);
    freeChannel(ps->server_channel);

    ssh_disconnect(ps->client_session);
    ssh_disconnect(ps->server_session);

    ssh_free(ps->client_session);
    ssh_free(ps->server_session);
    free(ps);
}

int proxyOpenServerSession(proxy_session* ps){
    if (!ssh_is_connected(ps->server_session)){
        ssh_options_set(ps->server_session, SSH_OPTIONS_HOST, "localhost");
        ssh_options_set(ps->server_session, SSH_OPTIONS_PORT_STR, "22");
        if (ssh_connect(ps->server_session) != SSH_OK){
            printf("Error connecting to target: %s\n", ssh_get_error(ps->server_session));
            ssh_disconnect(ps->server_session);
            return SSH_ERROR;
        }
    }
    return SSH_OK;
}

// Handle session

int handle_auth_none(ssh_session session, const char *user, proxy_session* ps){
    if (proxyOpenServerSession(ps)!=SSH_OK) return SSH_AUTH_AGAIN;

    if (ssh_userauth_none(ps->server_session, user)!=SSH_AUTH_SUCCESS){
        printf( "Error with none authentication: %s\n",ssh_get_error(ps->server_session));
        return SSH_AUTH_DENIED;
    }
    return SSH_AUTH_SUCCESS;
}

int handle_auth_password(ssh_session session, const char *user, const char *password,proxy_session *ps){
    if (proxyOpenServerSession(ps)!=SSH_OK) return SSH_AUTH_AGAIN;

    if (ssh_userauth_password(ps->server_session, user,password)!=SSH_AUTH_SUCCESS){
        printf( "Error with password authentication: %s\n",ssh_get_error(ps->server_session));
        return SSH_AUTH_DENIED;
    }
    return SSH_AUTH_SUCCESS;
}

// Channel 

int handle_pty_request(ssh_session session,ssh_channel channel,const char *term,int width, int height,int pxwidth, int pwheight,void *other){
    puts("handle_pty_request");
    return ssh_channel_request_pty_size(other,term,width,height);
}

int handle_shell_request(ssh_session session, ssh_channel channel, void* other){
    puts("handle_shell_request");
    return ssh_channel_request_shell(other);
}

int handle_channel_data(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void* other){
    printf("handle_channel_data from %p to %p\n",channel,other);
    return ssh_channel_write(other,data,len);
}

int handle_exec_request(ssh_session session, ssh_channel channel, const char *command, void* other){
    puts("handle_channel_exec");
    return ssh_channel_request_exec(other,command);
}

void handle_auth_agent_request(ssh_session session,ssh_channel channel,void *other){
    puts("handle_auth_agent_request");
    ssh_channel_request_auth_agent(other);
}

void handle_channel_close(ssh_session session,ssh_channel channel,void *other){
    puts("handle_channel_close");
    ssh_channel_close(other);
}

int handle_env_request(ssh_session session,ssh_channel channel,const char *env_name,const char *env_value,void *other){
    puts("handle_env_request");
    return ssh_channel_request_env(other,env_name,env_value);
}

void handle_channel_eof(ssh_session session,ssh_channel channel,void *other){
    puts("handle_channel_eof");
    ssh_channel_send_eof(other);
}

void handle_channel_exit_signal(ssh_session session,ssh_channel channel,const char *signal,int core,const char *errmsg,const char *lang,void *other){
    puts("handle_channel_exit_signal");
    ssh_channel_request_send_exit_signal(other,signal,core,errmsg,lang);
}

void handle_channel_exit_status(ssh_session session,ssh_channel channel,int exit_status,void *other){
    puts("handle_channel_exit_status");
    ssh_channel_request_send_exit_status(other,exit_status);
}

int handle_channel_pty_window_change(ssh_session session,ssh_channel channel,int width, int height,int pxwidth, int pwheight,void *other){
   puts("handle_channel_pty_window_change"); 
   return ssh_channel_request_pty_size(other,NULL,height,width);
}

void handle_channel_signal(ssh_session session,ssh_channel channel,const char *signal,void *other){
    puts("handle_channel_signal");
    ssh_channel_request_send_signal(other,signal);
}

int handle_channel_subsystem_request(ssh_session session,ssh_channel channel,const char *subsystem,void *other){
    puts("handle_channel_subsystem_request");
    return ssh_channel_request_subsystem(other,subsystem);
}

int handle_channel_write_wontblock(ssh_session session,ssh_channel channel,uint32_t bytes,void *other){
    printf("handle_channel_write_wontblock %d\n",bytes);
    ssh_channel_set_blocking(other,bytes);
    return 0;
}

void handle_channel_x11_request(ssh_session session,ssh_channel channel,int single_connection,const char *auth_protocol,const char *auth_cookie,uint32_t screen_number,void *other){
    puts("handle_channel_x11_request");
    ssh_channel_request_x11(other,single_connection,auth_protocol,auth_cookie,screen_number);
}


ssh_channel_callbacks allocChannelCallbacks(ssh_channel other){
    ssh_channel_callbacks ccb=malloc(sizeof(struct ssh_channel_callbacks_struct));
    *ccb=(struct ssh_channel_callbacks_struct){
        .channel_pty_request_function = handle_pty_request,
        .channel_shell_request_function = handle_shell_request,
        .channel_data_function= handle_channel_data,
        .channel_exec_request_function= handle_exec_request,
        .channel_auth_agent_req_function=handle_auth_agent_request,
        .channel_close_function=handle_channel_close,
        .channel_env_request_function=handle_env_request,
        .channel_eof_function=handle_channel_eof,
        .channel_exit_signal_function=handle_channel_exit_signal,
        .channel_exit_status_function=handle_channel_exit_status,
        .channel_pty_window_change_function=handle_channel_pty_window_change,
        .channel_signal_function=handle_channel_signal,
        .channel_subsystem_request_function=handle_channel_subsystem_request,
        .channel_write_wontblock_function=handle_channel_write_wontblock,
        .channel_x11_req_function=handle_channel_x11_request,
        .userdata=other
    };
    ssh_callbacks_init(ccb);
    return ccb;
}

ssh_channel handle_channel_creation(ssh_session session, proxy_session *ps){
    if (!(ps->client_channel=ssh_channel_new(ps->client_session))){
        fprintf(stderr,"Cannot create client channel");
        return NULL;
    }
    if (!(ps->server_channel=ssh_channel_new(ps->server_session))){
        fprintf(stderr,"Cannot create server channel");
        return NULL;
    }

    if (ssh_channel_open_session(ps->server_channel)!=SSH_OK){
        printf("ssh_channel_open_session: %s\n", ssh_get_error(ps->server_channel));
        return NULL;
    }

    ps->client_channel_callbacks=allocChannelCallbacks(ps->server_channel);
    ssh_set_channel_callbacks(ps->client_channel,ps->client_channel_callbacks);
    ps->server_channel_callbacks=allocChannelCallbacks(ps->client_channel);
    ssh_set_channel_callbacks(ps->server_channel,ps->server_channel_callbacks);

    return ps->client_channel;
}

// Handle each session

void handle_proxy_session(proxy_session* ps){
    if (ssh_handle_key_exchange(ps->client_session)!=SSH_OK) {
        printf("ssh_handle_key_exchange: %s\n", ssh_get_error(ps->client_session));
        return freeProxySession(ps);
    }

    struct ssh_server_callbacks_struct server_callbacks={
        .auth_none_function=(void*)handle_auth_none,
        .auth_password_function=(void*)handle_auth_password,
        .channel_open_request_session_function=(void*)handle_channel_creation,
        .userdata=ps
    };

    ssh_callbacks_init(&server_callbacks);

    if ( ssh_set_server_callbacks(ps->client_session, &server_callbacks)!=SSH_OK) {
        printf("ssh_set_server_callbacks: %s\n", ssh_get_error(ps->client_session));
        return freeProxySession(ps);
    }
    
    ssh_set_auth_methods(ps->client_session,SSH_AUTH_METHOD_NONE | SSH_AUTH_METHOD_PASSWORD);

    ssh_event mainloop = ssh_event_new();
    ssh_event_add_session(mainloop, ps->client_session);

    while (ssh_event_dopoll(mainloop, -1)!=SSH_ERROR);

    printf("Ending session : %s\n",ssh_get_error(ps->client_session));
    return freeProxySession(ps);
}

// Main part

ssh_bind sshbind=NULL;

void handle_exit(int signum) {
    printf("\nExiting...\n");
    if (sshbind) ssh_bind_free(sshbind);
    ssh_finalize();
    exit(EXIT_SUCCESS);
}

int main(){
    if (ssh_init() != SSH_OK) {
        fprintf(stderr, "Failed to initialize libssh.\n");
        return EXIT_FAILURE;
    }

    sshbind=ssh_bind_new();
    proxy_session* proxySession=NULL;
    pthread_t session_thread;


    ssh_bind_options_set(sshbind,SSH_BIND_OPTIONS_BINDPORT_STR,"2222");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, "id_rsa");
    

    if (ssh_bind_listen(sshbind)==SSH_OK){
        printf("Listening on port 2222...\n");

        if (signal(SIGINT, handle_exit) == SIG_ERR) {
            perror("Signal registration failed");
            return 1;
        }

        while (1){
            proxySession=newProxySession();

            if(ssh_bind_accept(sshbind, proxySession->client_session) != SSH_ERROR){
                if (pthread_create(&session_thread,NULL,(void*)handle_proxy_session,proxySession)==0){
                    fprintf(stdout,"new session in thread %ld\n",session_thread);
                    pthread_detach(session_thread);
                }else{
                    fprintf(stderr,"failed to create thread: running session in main thread");
                    handle_proxy_session(proxySession);
                }
            }
       }

    }else{
        fprintf(stderr, "ssh_bind_listen: %s.\n",ssh_get_error(sshbind));
    }

    
    handle_exit(0);
}