//
// Created by parallels on 9/28/16.
//
#include <stdio.h>
#include <time.h>
#include <jwt.h>

int main(int argc, char* argv[]) {

    unsigned char key256[1024] = "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIICXAIBAAKBgQDg5A1uZ5F36vQEYbMWCV4wY4OVmicYWEjjl/8YPA01tsz4x68i"
            "/NnlMNalqpGCIZ0AwqGI5DZAWWoR400L3SAmYD6sWj2L9ViIAPk3ceDU8olYrf/N"
            "wj78wVoG7qqNLgMoBNM584nlY4jy8zJ0Ka9WFBS2aDtB3Aulc1Q8ZfhuewIDAQAB"
            "AoGAfD+C7CxsQkSc7I7N0q76SuGwIUc5skmUe6nOViVXZwXH2Or55+qqt+VzsbO7"
            "EJphk7n0ZR0wm/zKjXd3acaRq5j3fOyXip9fDoNj+oUKAowDJ9vub0NOPpU2bgb0"
            "xDnDeR0BRVBOTWqrkDeDPBSxw5RlJunesDkamAmj4VXHHgECQQDzqDtaEuEZ7x7d"
            "kJKCmfGyP01s+YPlquDgogzAeMAsz17TFt8JS4RO0rX71+lmx7qqpRqIxVXIsR58"
            "NI2Th7tRAkEA7Eh1C1WahLCxojQOam/l7GyE+2ignZYExqonOOvsk6TG0LcFm7W9"
            "x39ouTlfChM26f8VYAsPxIrvsDlI1DDCCwJBAITmA8lzdrgQhwNOsbrugLg6ct63"
            "kcuZUqLzgIUS168ZRJ1aYjjNqdLcd0pwT+wxkI03FKv5Bns6sGgKuhX3+KECQFm/"
            "Z93HRSrTZpViynr5R88WpShNZHyW5/eB1+YSDslB1FagvhuX2570MRXxybys8bXN"
            "sxPI/9M6prI8AALBBmMCQD+2amH2Y9ukJy10WuYei943mrCsp1oosWjcoMADRCpj"
            "ZA2UwSzj67PBc5umDIAlhVRMX0zH/gLj54rfIkH5zLk=\n"
            "-----END RSA PRIVATE KEY-----";

    jwt_t *jwt = NULL;
    int ret = 0;
    char *out;

    ret = jwt_new(&jwt);
    if (ret != 0)
        printf("failed creation\n");

    // "iss" /* service account email address */
    ret = jwt_add_grant(jwt, "iss", "festivus@dalhart-project-421.iam.gserviceaccount.com");
    if (ret != 0)
        printf("failed iss grant\n");

    // "scope" /* scope of requested access token */;
    ret = jwt_add_grant(jwt, "scope", "https://www.googleapis.com/auth/storage");
    if (ret != 0)
        printf("failed scope\n");

    // "aud" = "https://accounts.google.com/o/oauth2/token"; /* intended target of the assertion for an access token */
    ret = jwt_add_grant(jwt, "aud", "https://accounts.google.com/o/oauth2/token");
    if (ret != 0)
        printf("failed aud\n");

    time_t rawtime;
    time (&rawtime);
    char start_time[16];
    snprintf(start_time, 16, "%lu", rawtime);
    char expire_time[16];
    snprintf(expire_time, 16, "%lu", rawtime + 3600);

    ret = jwt_add_grant(jwt, "iat", start_time);
    if (ret != 0)
        printf("failed iat\n");

    ret = jwt_add_grant(jwt, "exp", expire_time);
    if (ret != 0)
        printf("failed exp\n");

//    out = jwt_encode_str(jwt);
//    if (out == NULL)
//        printf("filename out fail");
//
//
//    printf("filename name regex :%s\n", out);
    // jwt_claim_set["iad"] = std::to_string(t); /* issued time */

    // jwt_claim_set["exp"] = std::to_string(t+3600); /* expire time*/

    //ret = jwt_set_alg_rsa(jwt, JWT_ALG_RS256, rsa);
    ret = jwt_set_alg(jwt, JWT_ALG_RS256, key256, sizeof(key256));
    if (ret != 0)
        printf("failed jwt_set_alg\n");


    out = jwt_encode_str(jwt);
    if (out == NULL)
        printf("filename out fail\n");

    printf("encoded message : %s\n", out);

    free(out);

    jwt_free(jwt);

//    unsigned char key256[1024] = "-----BEGIN RSA PRIVATE KEY-----\n"
//            "MIICXAIBAAKBgQDg5A1uZ5F36vQEYbMWCV4wY4OVmicYWEjjl/8YPA01tsz4x68i"
//            "/NnlMNalqpGCIZ0AwqGI5DZAWWoR400L3SAmYD6sWj2L9ViIAPk3ceDU8olYrf/N"
//            "wj78wVoG7qqNLgMoBNM584nlY4jy8zJ0Ka9WFBS2aDtB3Aulc1Q8ZfhuewIDAQAB"
//            "AoGAfD+C7CxsQkSc7I7N0q76SuGwIUc5skmUe6nOViVXZwXH2Or55+qqt+VzsbO7"
//            "EJphk7n0ZR0wm/zKjXd3acaRq5j3fOyXip9fDoNj+oUKAowDJ9vub0NOPpU2bgb0"
//            "xDnDeR0BRVBOTWqrkDeDPBSxw5RlJunesDkamAmj4VXHHgECQQDzqDtaEuEZ7x7d"
//            "kJKCmfGyP01s+YPlquDgogzAeMAsz17TFt8JS4RO0rX71+lmx7qqpRqIxVXIsR58"
//            "NI2Th7tRAkEA7Eh1C1WahLCxojQOam/l7GyE+2ignZYExqonOOvsk6TG0LcFm7W9"
//            "x39ouTlfChM26f8VYAsPxIrvsDlI1DDCCwJBAITmA8lzdrgQhwNOsbrugLg6ct63"
//            "kcuZUqLzgIUS168ZRJ1aYjjNqdLcd0pwT+wxkI03FKv5Bns6sGgKuhX3+KECQFm/"
//            "Z93HRSrTZpViynr5R88WpShNZHyW5/eB1+YSDslB1FagvhuX2570MRXxybys8bXN"
//            "sxPI/9M6prI8AALBBmMCQD+2amH2Y9ukJy10WuYei943mrCsp1oosWjcoMADRCpj"
//            "ZA2UwSzj67PBc5umDIAlhVRMX0zH/gLj54rfIkH5zLk=\n"
//            "-----END RSA PRIVATE KEY-----";
//    jwt_t *jwt = NULL;
//    int ret = 0;
//    char *out;
//
//    ret = jwt_new(&jwt);
//
//    ret = jwt_add_grant(jwt, "iss", "files.cyphre.com");
//
//    ret = jwt_add_grant(jwt, "sub", "user0");
//
//    ret = jwt_add_grant(jwt, "ref", "XXXX-YYYY-ZZZZ-AAAA-CCCC");
//
//    ret = jwt_set_alg(jwt, JWT_ALG_RS256, key256, sizeof(key256));
//
//    out = jwt_encode_str(jwt);
//
//    free(out);
//
//    jwt_free(jwt);


    return 0;
}