/* -*-mode: flex-*- */


%option nounput

%{

/*  gpdump-scanner.l
 *
 *
 *  gpdump 0.3, Copyright (c) 2009 Grzegorz Pawelski <grzegorz.pawelski@nsn.com>
 */

#include <stdio.h>
#include <stdlib.h>

#include "gpdump.h"

#ifdef _WIN32
#include <windows.h>
#endif

extern unsigned int follow_flag;

%}


time "MONITORING TIME:"
received "RECEIVED BY:"
sent "SENT BY:"
message "MONITORED MESSAGE:"
header [0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]/[ \t\n\r]
byte [0-9A-Fa-f][0-9A-Fa-f]/[ \t\n\r]
time_details [0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9]/[ \t\n\r]
text [^ \n\t]+
eol \r?\n\r?



%%

{byte}            { parse_token_yy(T_BYTE, yytext); }
{header}          { parse_token_yy(T_HEADER, yytext); }
{time}            { parse_token_yy(T_TIME, yytext); }
{received}        { parse_token_yy(T_RECEIVED, yytext); }
{sent}            { parse_token_yy(T_SENT, yytext); }
{message}         { parse_token_yy(T_MESSAGE, yytext); }
{time_details}    { parse_token_yy(T_TIME_DETAILS, yytext); }
{text}            ;
{eol}             ;
[ \t]             ;


%%

int yywrap()
{
    if (follow_flag == 1)
    {
#if _WIN32 
        Sleep(1000);
#else
        sleep(1);
#endif
        yylex();
    }
    return 1;
}
