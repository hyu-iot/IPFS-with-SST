#include "../c_api.h"

int main(int argc, char *argv[]) {
    char *config_path = argv[1];
    SST_ctx_t *ctx = init_SST(config_path);

    session_key_list_t *s_key_list = get_session_key(ctx, NULL);
    SST_session_ctx_t *session_ctx =
        secure_connect_to_server(&s_key_list->s_key[0], ctx);
    
    sleep(3);
    file_encrypt_upload(session_ctx);
    sleep(3);
    // transfer the information including hash value, request info, response info, sessionkey id.
    upload_to_datamanagement(session_ctx, ctx);

    free(session_ctx);

    free_session_key_list_t(s_key_list);

    free_SST_ctx_t(ctx);

    sleep(3);
}
