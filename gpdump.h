
/*  gpdump.h
 *
 *
 *  gpdump 0.3, Copyright (c) 2009 Grzegorz Pawelski <grzegorz.pawelski@nsn.com>
 */

typedef enum {
    T_BYTE = 1,
    T_HEADER,
    T_TIME,
    T_RECEIVED,
    T_SENT,
    T_MESSAGE,
    T_TEXT,
    T_TIME_DETAILS
} token_t;

typedef enum {
    T_BYTE_DPD = 1,
    T_TIME_DPD,
    T_END
} token_dpd_t;


void parse_token_yy(token_t token, char *str);
void parse_token_dpd(token_dpd_t token, char *str);

int yylex(void);
int dpdlex(void);
