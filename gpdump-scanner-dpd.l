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


time \[[0-9]*.[0-9][0-9][0-9]\]
byte [0-9A-Fa-f][0-9A-Fa-f]/[ \t\n\r]
end ^[\n\r]
text [^ \n\t]+




%%

{time}            { parse_token_dpd(T_TIME_DPD, yytext); }
{byte}            { parse_token_dpd(T_BYTE_DPD, yytext); }
{end}             { parse_token_dpd(T_END, yytext); }
{text}            ;
[\n\r]            ;
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
        dpdlex();
    }
    return 1;
}
