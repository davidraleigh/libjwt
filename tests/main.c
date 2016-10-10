//
// Created by david raleigh on 9/28/16.
//
#include <stdio.h>
#include <time.h>
#include <jwt.h>
#include <jansson.h>
#include <curl/curl.h>
#include <string.h>

struct string {
    char *ptr;
    size_t len;
};

void init_string(struct string *s) {
    s->len = 0;
    s->ptr = calloc(s->len+1, 1);
    if (s->ptr == NULL) {
        fprintf(stderr, "malloc() failed\n");
        exit(EXIT_FAILURE);
    }
    s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
    size_t new_len = s->len + size*nmemb;
    s->ptr = realloc(s->ptr, new_len+1);
    if (s->ptr == NULL) {
        fprintf(stderr, "realloc() failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(s->ptr+s->len, ptr, size*nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size*nmemb;
}

int create_jwt_assertion(char *client_email_text,
                         char *scope,
                         char *aud,
                         char *private_key_text,
                         int duration_s,
                         char **jwt_assertion) {
    int ret = 0;
    char *out;
    jwt_t *jwt = NULL;

    if (jwt_new(&jwt) != 0) {
        printf("failed creation\n");
        return 1;
    }

    // "iss" /* service account email address */
    ret = jwt_add_grant(jwt, "iss", client_email_text);
    if (ret != 0) {
        printf("failed iss grant\n");
        return 1;
    }


    // "scope" /* scope of requested access token */;
    //devstorage.read_only
    ret = jwt_add_grant(jwt, "scope", scope);//"https://www.googleapis.com/auth/devstorage.read_only");
    if (ret != 0)
    {
        printf("failed scope\n");
        return 1;
    }

    // "aud" = "https://accounts.google.com/o/oauth2/token"; /* intended target of the assertion for an access token */
    ret = jwt_add_grant(jwt, "aud", aud);
    if (ret != 0){
        printf("failed aud\n");
        return 1;
    }

    time_t rawtime;
    time(&rawtime);
    char start_time[16];
    snprintf(start_time, 16, "%lu", rawtime);
    char expire_time[16];
    snprintf(expire_time, 16, "%lu", rawtime + duration_s);

    ret = jwt_add_grant(jwt, "iat", start_time);
//    ret = jwt_add_grant(jwt, "iat", "1475467787");
    if (ret != 0) {
        printf("failed iat\n");
        return 1;
    }

    ret = jwt_add_grant(jwt, "exp", expire_time);
//    ret = jwt_add_grant(jwt, "exp", "1475471387");
    if (ret != 0) {
        printf("failed exp\n");
        return 1;
    }

    //ret = jwt_set_alg_rsa(jwt, JWT_ALG_RS256, rsa);
    ret = jwt_set_alg(jwt, JWT_ALG_RS256, private_key_text, strlen(private_key_text));
    if (ret != 0) {
        printf("failed jwt_set_alg\n");
        return 1;
    }


    out = jwt_encode_str(jwt);
    if (out == NULL) {
        printf("jwt assertion out fail\n");
        return 1;
    }

    *jwt_assertion = out;

    jwt_free(jwt);

    return 0;
};

int jwt_service_acct_json(char *json_file, char **jwt_assertion) {
    FILE *fp = fopen ( json_file , "rb" );
    long length = 0;
    char *buffer = 0;

    if (fp)
    {
        fseek (fp, 0, SEEK_END);
        length = ftell (fp);
        fseek (fp, 0, SEEK_SET);
        buffer = calloc (length + 1, 1);
        if (!buffer) {
            fclose (fp);
            return 1;
        }
        size_t n_read = fread (buffer, 1, length, fp);
        size_t n_buffer = (size_t) length;
        fclose (fp);
        if (n_read != n_buffer) {
            free(buffer);
            return 1;
        }

    } else {
        perror(json_file);
        return 1;
    }

    json_t *root;
    json_error_t error;
    json_t *private_key, *client_email, *token_uri;

    root = json_loads(buffer, 0, &error);
    free(buffer);

    if(!root)
    {
        fprintf(stderr, "error: on line %d: %s\n", error.line, error.text);
        return 1;
    }

    if(!json_is_object(root))
    {
        fprintf(stderr, "error: root is not an object\n");
        json_decref(root);
        return 1;
    }

    private_key = json_object_get(root, "private_key");
    if(!json_is_string(private_key))
    {
        fprintf(stderr, "error: private_key is not a string\n");
        json_decref(root);
        return 1;
    }
    const char *private_key_text = json_string_value(private_key);

    client_email = json_object_get(root, "client_email");
    if(!json_is_string(client_email))
    {
        fprintf(stderr, "error: client_email is not an object\n");
        json_decref(root);
        return 1;
    }
    const char *client_email_text = json_string_value(client_email);

    token_uri = json_object_get(root, "token_uri");
    if(!json_is_string(token_uri))
    {
        fprintf(stderr, "error: token_uri is not a string\n");
        json_decref(root);
        return 1;
    }
    const char *token_uri_text = json_string_value(token_uri);

    return create_jwt_assertion(client_email_text,
                         "https://www.googleapis.com/auth/devstorage.read_only",
                         token_uri_text,
                         private_key_text,
                         3600,
                         &jwt_assertion);


};

int token_request(char *jwt_assertion, char **jwt_token) {
    CURL* curl;

    curl_global_init(CURL_GLOBAL_ALL);
    curl=curl_easy_init();
    if(!curl) {
        return 1;
    }

    struct string s;
    init_string(&s);

    curl_easy_setopt(curl, CURLOPT_URL, "https://accounts.google.com/o/oauth2/token");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    curl_easy_setopt(curl, CURLOPT_POST, 1);
    char grant_line[] = "grant_type=assertion&assertion_type=http%3A%2F%2Foauth.net%2Fgrant_type%2Fjwt%2F1.0%2Fbearer&assertion=";
    char *post_fields;

    if((post_fields = calloc(strlen(jwt_assertion)+strlen(grant_line) + 1, 1)) != NULL){
        post_fields[0] = '\0';   // ensures the memory is an empty string
        strcat(post_fields, grant_line);
        strcat(post_fields, jwt_assertion);
    } else {
        fprintf(stderr,"malloc failed!\n");
        return 1;
    }

    printf("postfields :%s\n", post_fields);

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields);
    curl_easy_perform(curl);

    printf("%s\n", s.ptr);
    *jwt_token = s.ptr;
    //free(s.ptr);


    curl_easy_cleanup(curl);
    curl_global_cleanup();

    free(post_fields);
    return 0;
}

int main(int argc, char* argv[]) {
    char* json_file = "/Users/davidraleigh/Downloads/Dalhart-35d3ffd7dfa7-festivus.json";
    char* jwt_assertion;
    int result = jwt_service_acct_json(json_file, &jwt_assertion);
    printf("filename name regex :%s\n", jwt_assertion);

    char *jwt_token;
    token_request(jwt_assertion, &jwt_token);
    printf("%s\n", jwt_token);
    free(jwt_assertion);
    return result;
}
