
/*  gpdump.c
 *
 *
 *  gpdump 0.3, Copyright (c) 2009 Grzegorz Pawelski <grzegorz.pawelski@nsn.com>
 */


#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <time.h>
#include <glib.h>

#include <errno.h>
#include <assert.h>

#define _GNU_SOURCE
#include <getopt.h>

#include "gpdump.h"

#if _WIN32
#include <winsock2.h>
#else
#include <fcntl.h>
#include <signal.h>
#endif


typedef enum {
    MONITOR_YY,
    DPDUMPGX_DPD
} parser_t;

static int parser_type;


typedef enum {
    INIT,     
    START_TIME,         
    START_MESSAGE_HEADER, 
    START_MESSAGE_DATA              
} parser_state_t;


typedef enum {
    NOTHING,
    M_E49E,
    M_0103_E978,  
    M_0103_E978_ITU,
    M_0103_E978_ANSI,
    M_EC71_EC72,
    DPD_ATM,
    DPD_ETH                
} message_t;

static int proto = NOTHING;

static parser_state_t state = INIT;


#define MESSAGE_HEADER_LENGTH 16
#define MTP_LENGTH_ITU 5
#define MTP_LENGTH_ANSI 8
#define FR_LENGTH 2

#define M_E49E_PAYLOAD_START 14       // 19 - SCCP, 14 - MTP3
#define M_0103_E978_PAYLOAD_START 36  // 36 - SCCP 
#define M_EC71_EC72_PAYLOAD_START 8   // 12 - BSSGP, 8 - GPRS-NS

#define DLT_MTP3 141
#define DLT_FRELAY 107
#define DLT_ATM 11
#define DLT_ETH 1

/* Link-layer type; see net/bpf.h for details */
static unsigned long pcap_link_type;


static message_t message_type;                                                   
static unsigned int header_length;


extern FILE *yyin;
extern FILE *dpdin;

unsigned int follow_flag = 0;

static unsigned int header_count, payload_start, payload_end, payload_count, length;  


static char *input_filename; 
static FILE *input_file = NULL;

static char *output_filename; 
static FILE *output_file = NULL;



#define	PCAP_MAGIC			0xa1b2c3d4


struct pcap_hdr {
    guint32	magic;		/* magic */
    guint16	version_major;	/* major version number */
    guint16	version_minor;	/* minor version number */
    guint32	thiszone;	/* GMT to local correction */
    guint32	sigfigs;	/* accuracy of timestamps */
    guint32	snaplen;	/* max length of captured packets, in octets */
    guint32	network;	/* data link type */
};


struct pcaprec_hdr {
    gint32	ts_sec;		/* timestamp seconds */
    guint32	ts_usec;	/* timestamp microseconds */
    guint32	incl_len;	/* number of octets of packet saved in file */
    guint32	orig_len;	/* actual length of packet */
};



static gint32 ts_sec  = 0;
static guint32 ts_usec = 0;
static struct timeval start_time_dpd;

#define MAX_PACKET 64000
static unsigned char packet_buf[MAX_PACKET];
static unsigned long curr_offset = 0;
static unsigned long max_offset = MAX_PACKET;
static unsigned long packet_start = 0;

/* Offset base to parse */
static unsigned long offset_base = 16;

/* Fake MTP3 header */
static guint8 mtp3_sio;

static guint32 mtp3_rl;

static struct ansi_mtp3_rl_t {
   guint8 dpc_memb;
   guint8 dpc_clust;
   guint8 dpc_net;
   guint8 opc_memb;
   guint8 opc_clust;
   guint8 opc_net;
   guint8 sls;
} ansi_mtp3_rl;


/* Fake FR header */
static guint16 fr_header;




static void
write_file_header (void)
{
    struct pcap_hdr fh;

    fh.magic = PCAP_MAGIC;
    fh.version_major = 2;
    fh.version_minor = 4;
    fh.thiszone = 0;
    fh.sigfigs = 0;
    fh.snaplen = 102400;
    fh.network = pcap_link_type;

    fwrite(&fh, sizeof(fh), 1, output_file);
    fflush(output_file);
}



static void
write_current_packet (void)
{
    struct pcaprec_hdr ph;
    ph.ts_sec = ts_sec;
    ph.ts_usec = ts_usec;
    ph.incl_len = curr_offset + header_length;
    ph.orig_len = curr_offset + header_length;

#ifndef _WIN32
    goto skip;

restart:
    fclose(output_file);
    output_file = fopen(output_filename, "wb");
    write_file_header();
#endif

skip:
    fwrite(&ph, sizeof(ph), 1, output_file);

    switch(message_type)
    {
    case M_0103_E978:
        fwrite(&mtp3_sio, sizeof(mtp3_sio), 1, output_file);
        switch(proto)
        {
        case M_0103_E978_ITU:
            fwrite(&mtp3_rl, sizeof(mtp3_rl), 1, output_file);
            break;
        case M_0103_E978_ANSI:
            fwrite(&ansi_mtp3_rl, sizeof(ansi_mtp3_rl), 1, output_file);
            break;
        }
        break;
    case M_EC71_EC72:
        fr_header = htons(fr_header);
        fwrite(&fr_header, sizeof(fr_header), 1, output_file); 
        break;
    } 
    fwrite(packet_buf, curr_offset, 1, output_file);
    fflush(output_file);
#ifndef _WIN32
    if (ferror(output_file)) goto restart;
#endif
}



static unsigned long
parse_num (char *str, int offset)
{
    unsigned long num;
    char *c;

    num = strtoul(str, &c, offset ? offset_base : 16);
    if (c==str) 
    {
        fprintf(stderr, "FATAL ERROR: Bad hex number? [%s]\n", str);
        exit(-1);
    }
    return num;
}




static void
write_byte (char *str)
{
    unsigned long num;

    num = parse_num(str, FALSE);
    packet_buf[curr_offset] = (unsigned char) num;
    curr_offset ++; 
    if (curr_offset >= max_offset) state = INIT;
}



void
parse_time (token_t token, char *str)
{
    struct tm *c_time;
    time_t rawtime;
    char buf_time[20];
    char buf_conv[20];    

    strncpy(buf_time, str, 12); 
 
    time(&rawtime);
    c_time = localtime(&rawtime);

    strncpy(buf_conv, &buf_time[0], 2); 
    buf_conv[2] = '\0';
    c_time->tm_hour = atoi(buf_conv);

    strncpy(buf_conv, &buf_time[3], 2); 
    buf_conv[2] = '\0';
    c_time->tm_min = atoi(buf_conv);

    strncpy(buf_conv, &buf_time[6], 2); 
    buf_conv[2] = '\0';
    c_time->tm_sec = atoi(buf_conv);

    strncpy(buf_conv, &buf_time[9], 2); 
    buf_conv[2] = '\0';
    ts_usec = atoi(buf_conv) * 10000;

    ts_sec = mktime(c_time);    

    state = INIT; 
}


void
parse_message_header (token_t token, char *str)
{
    switch(header_count++) 
    {
    case 0:        
        sscanf(str, "%X", &length);
        break; 
    case 2:      
        switch(message_type)
        {
        case M_E49E:
            if (strncmp(str, "030D", strlen(str)) == 0); 
            else state = INIT;
            break; 
        case M_0103_E978:
            if (strncmp(str, "0208", strlen(str)) == 0); 
            else state = INIT;
            break; 
        case M_EC71_EC72:
            if (strncmp(str, "0403", strlen(str)) == 0); 
            else state = INIT;
            break; 
        }
        break;
    case 7: 
        switch(message_type)
        {
        case M_E49E:
            if (strncmp(str, "E49E", strlen(str)) == 0)
            {
                payload_start = M_E49E_PAYLOAD_START;
                if (length - MESSAGE_HEADER_LENGTH > M_E49E_PAYLOAD_START) 
                {
                    payload_end = length - MESSAGE_HEADER_LENGTH - 1;
                } 
                else state = INIT; 
            }
            else state = INIT;
            break;
        case M_0103_E978:
            if (strncmp(str, "0103", strlen(str)) == 0 || strncmp(str, "E978", strlen(str)) == 0)
            {
                payload_start = M_0103_E978_PAYLOAD_START;
                if (length - MESSAGE_HEADER_LENGTH > M_0103_E978_PAYLOAD_START) 
                {
                    payload_end = length - MESSAGE_HEADER_LENGTH - 1;
                } 
                else state = INIT; 
            }
            else state = INIT;
            break;
        case M_EC71_EC72:
            if (strncmp(str, "EC72", strlen(str)) == 0 || strncmp(str, "EC71", strlen(str)) == 0)
            {
                payload_start = M_EC71_EC72_PAYLOAD_START;
                if (length - MESSAGE_HEADER_LENGTH > M_EC71_EC72_PAYLOAD_START)
                {
                    payload_end = length - MESSAGE_HEADER_LENGTH - 1;
                } 
                else state = INIT; 
            }
            else state = INIT;
            break; 
        }
        break;

    case 8:
        state = START_MESSAGE_DATA;
        payload_count = 0;
        curr_offset = 0;
        break;
    }
}


 
void
parse_message_data_M_E49E (token_t token, char *str)
{
    if (payload_count >= payload_start) write_byte(str);   

    if (++payload_count > payload_end) 
    {
        state = INIT;
        write_current_packet();
    }  
}      


void
parse_message_data_M_0103_E978 (token_t token, char *str)
{
    static char topc[5];
    static char tdpc[5];
    static guint32 sls, opc, dpc;

    if (payload_count >= payload_start) write_byte(str); 
    else
    { 
        switch(proto)
        {
        case M_0103_E978_ITU:
            switch(payload_count)
            {
            case 11:
                sscanf(str, "%X", &sls);
                break;
            case 16:
                strncpy(&tdpc[2], str, 2);
                break;
            case 17:
                strncpy(tdpc, str, 2);
                tdpc[4] = '\0';
                sscanf(tdpc, "%X", &dpc);
                break;
            case 20:
                strncpy(&topc[2], str, 2);
                break;
            case 21:
                strncpy(topc, str, 2);
                topc[4] = '\0';
                sscanf(topc, "%X", &opc);
                sls = sls << 28;
                opc = opc << 18;
                opc = opc >> 4;
                dpc = dpc << 18;
                dpc = dpc >> 18;
                mtp3_rl = sls + opc + dpc;
                break;
            case 32:
                mtp3_sio = (guint8) (parse_num(str, FALSE));
                break;
            }
            break;
        case M_0103_E978_ANSI:
            switch(payload_count)
            {
            case 11:
                ansi_mtp3_rl.sls = (guint8) (parse_num(str, FALSE));
                break;
            case 16:
                ansi_mtp3_rl.dpc_memb = (guint8) (parse_num(str, FALSE));
                break;
            case 17:
                ansi_mtp3_rl.dpc_clust = (guint8) (parse_num(str, FALSE));
                break;
            case 18:
                ansi_mtp3_rl.dpc_net = (guint8) (parse_num(str, FALSE));
                break;
            case 20:
                ansi_mtp3_rl.opc_memb = (guint8) (parse_num(str, FALSE));
                break;
            case 21:
                ansi_mtp3_rl.opc_clust = (guint8) (parse_num(str, FALSE));
                break;
            case 22:
                ansi_mtp3_rl.opc_net = (guint8) (parse_num(str, FALSE));
                break;
            case 32:
                mtp3_sio = (guint8) (parse_num(str, FALSE));
                break;
            }
            break;
        } 
    }  

    if (++payload_count > payload_end) 
    {
        state = INIT;
        write_current_packet();
    }  
}    


void
parse_message_data_M_EC71_EC72 (token_t token, char *str)
{
    static char tdlci[5];
    static guint16 dlci, dlci1, dlci2;

    if (payload_count >= payload_start) write_byte(str);   
    else
    { 
        switch(payload_count)
        {
        case 2:
            strncpy(&tdlci[2], str, 2);
            break;
        case 3:
            strncpy(tdlci, str, 2);                                  
            tdlci[4] = '\0';
            sscanf(tdlci, "%X", &dlci);
            dlci = dlci << 6;
            dlci = dlci >> 2;
            dlci1 = dlci & 0x00F0;
            dlci1 = dlci1 | 0x0001;            
            dlci2 = dlci & 0x3F00;
            dlci2 = dlci2 << 2;
            fr_header = dlci1 + dlci2; 
            break; 
        }   
    }

    if (++payload_count > payload_end) 
    {
        state = INIT;
        write_current_packet();
    }
}      


/* Message monitor parsing */

void
parse_token_yy (token_t token, char *str)
{
    if (token == T_TIME) state = INIT;
    switch(state) 
    {
    case INIT:
        switch(token) 
        {
        case T_MESSAGE:
            state = START_MESSAGE_HEADER;
            header_count = 0;
            break;
        case T_TIME:
            state = START_TIME;
            break; 
        } 
        break;
    case START_TIME:
        switch(token) 
        {
        case T_TIME_DETAILS:
            parse_time(token, str);
            break;
        }
        break;      
    case START_MESSAGE_HEADER:
        switch(token) 
        {
        case T_HEADER:
            parse_message_header(token, str);
            break;
        case T_BYTE:
            parse_message_header(token, str);
            break;
        }
        break;
    case START_MESSAGE_DATA:
        switch(token) 
        {
        case T_BYTE:
            switch(message_type)
            {
            case M_E49E:
                parse_message_data_M_E49E(token, str);
                break; 
            case M_0103_E978:
                parse_message_data_M_0103_E978(token, str);
                break; 
            case M_EC71_EC72:
                parse_message_data_M_EC71_EC72(token, str);
                break; 
            }
            break;
        }
        break;
    }
}


/* DPDUMPGX parsing */

void
parse_time_dpd (char *str)
{
    struct tm *c_time;
    time_t time_secs;
    int i = 1, j = 0;
    char buf_conv_sec[20];
    char buf_conv_usec[20];    

    while (str[i]!='.' && str[i]!='\0' && j < 20)
    {
        buf_conv_sec[j++] = str[i++];
    }
    buf_conv_sec[j] = '\0';
    i++;
    j = 0;
    while (str[i]!=']' && str[i]!='\0' && j < 20)
    {
        buf_conv_usec[j++] = str[i++];
    }
    buf_conv_usec[j] = '\0';
     
    time_secs = start_time_dpd.tv_sec + atoi(buf_conv_sec);    
    c_time = localtime (&time_secs); 

    ts_usec = atoi(buf_conv_usec) * 1000; 
    ts_sec = mktime(c_time);
}


void
parse_token_dpd (token_dpd_t token, char *str)
{
    if (token == T_TIME_DPD) state = INIT;
    switch(state) 
    {
    case INIT:
        switch(token) 
        {
        case T_TIME_DPD:
            parse_time_dpd(str);
            state = START_MESSAGE_DATA;
            curr_offset = 0;
            break;
        }
        break;
    case START_MESSAGE_DATA:
        switch(token) 
        { 
        case T_BYTE_DPD:
            write_byte(str);
            break;
        case T_END:
            state = INIT;
            write_current_packet();
            break;
        }
        break;
    }
}



void
help()
{
    fprintf(stderr, 
            "\n"
            "usage:  gpdump {-h|--help|-v|--version} \n"
            "        gpdump [-o|--online] -mtp3b|-itu-mtp3|-ansi-mtp3|-frelay input_file [output_file] \n"
            "        gpdump [-o|--online] -atm|-eth input_file [output_file] \n"
            "\n"
            "        -h --help                                 help \n"
            "        -v --version                              version \n"
            "\n"
            "        -o --online                               online (live) capture like \"tail -f\" \n"
            "\n"
            "\n"
            "        -mtp3b -itu-mtp3 -ansi-mtp3 -frelay       protocol \n"
            "\n"
            "        -mtp3b       processes E49E messages from PAPUs \n"
            "        -itu-mtp3    processes 0103 and E978 messages from SMMUs (ITU) \n"
            "        -ansi-mtp3   processes 0103 and E978 messages from SMMUs (ANSI) \n"
            "        -frelay      processes EC71 and EC72 messages from PAPUs, \n"
            "                     please set gprs_ns in FR protocol settings in Wireshark, \n"
            "                     adding DLCI column in display is also very useful \n"  
            "\n"
            "\n"
            "        -atm -eth        interface type \n"    
            "\n"
            "        -atm         processes ATM link layer frames in hex from DPDUMPGX on ATM iface eg. X:::::AA4 \n"
            "        -eth         processes ETH link layer frames in hex from DPDUMPGX on ETH iface eg. X:::::EL0 \n"
            "\n");
    exit(-1);
}


static void
parse_options (int argc, char *argv[])
{
    extern char *optarg;
    extern int optind, opterr, optopt;
    int c;
    int option_index = 0;

    static struct option long_options[] = {
        {"online", 0, 0, 'o'},
        {"mtp3b", 0, &proto, M_E49E},
        {"itu-mtp3", 0, &proto, M_0103_E978_ITU},
        {"ansi-mtp3", 0, &proto, M_0103_E978_ANSI},
        {"frelay", 0, &proto, M_EC71_EC72},
        {"atm", 0, &proto, DPD_ATM},
        {"eth", 0, &proto, DPD_ETH},
        {"help", 0, 0, 'h'},
        {"version", 0, 0, 'v'},
        {0, 0, 0, 0}
    };


    while ((c = getopt_long_only(argc, argv, "ohv", long_options, &option_index)) != -1) 
    {
        switch(c) 
        {
        case 'o': follow_flag = 1; break;
        case 'h': help(); break;
        case 'v': fprintf(stderr, "\ngpdump 0.3, Copyright (c) 2009 Grzegorz Pawelski <grzegorz.pawelski@nsn.com>\n\n"); exit(-1);
        case 0:   break;
        default: help();
        }
    }


    switch(proto)
    {
    case M_E49E:
        message_type = M_E49E;
        header_length = 0;
        pcap_link_type = DLT_MTP3;
        parser_type = MONITOR_YY; 
        fprintf(stderr, "\n Protocol mtp3b - processing E49E messages from PAPU\n\n");
        break;
    case M_0103_E978_ITU:
        message_type = M_0103_E978;
        header_length = MTP_LENGTH_ITU;
        pcap_link_type = DLT_MTP3;
        parser_type = MONITOR_YY;
        fprintf(stderr, "\n Protocol ITU mtp3 - processing 0103 and E978 messages from SMMU,"
                        "\n please set ITU in MTP3 protocol settings in Wireshark\n\n");
        break;
    case M_0103_E978_ANSI:
        message_type = M_0103_E978;
        header_length = MTP_LENGTH_ANSI;
        pcap_link_type = DLT_MTP3;
        parser_type = MONITOR_YY;
        fprintf(stderr, "\n Protocol ANSI mtp3 - processing 0103 and E978 messages from SMMU,"
                        "\n please set ANSI in MTP3 protocol settings in Wireshark\n\n");
        break;
    case M_EC71_EC72:
        message_type = M_EC71_EC72;
        header_length = FR_LENGTH;
        pcap_link_type = DLT_FRELAY;
        parser_type = MONITOR_YY; 
        fprintf(stderr, "\n Protocol frelay - processing EC71 and EC72 messages from PAPU," 
                        "\n please set gprs_ns in FR protocol settings in Wireshark\n\n");
        break;
    case DPD_ATM:
        pcap_link_type = DLT_ATM;
        header_length = 0;
        parser_type = DPDUMPGX_DPD;
        fprintf(stderr, "\n Processing ATM link layer frames in hex from DPDUMPGX on ATM iface eg. X:::::AA4\n\n");
        break;
    case DPD_ETH:
        pcap_link_type = DLT_ETH;
        header_length = 0;
        parser_type = DPDUMPGX_DPD;
        fprintf(stderr, "\n Processing ETH link layer frames in hex from DPDUMPGX on ETH iface eg. X:::::EL0\n\n");
        break;
    default:
        fprintf(stderr, "\nNo protocol specified!\n\n");
        help();
    }

    if (argc > optind && argc-optind > 0) 
    {
        input_filename = strdup(argv[optind]); 
        fprintf(stderr, "\nInput filename: %s\n", input_filename);
        if (!(input_file = fopen(input_filename, "rb"))) 
        {
           fprintf(stderr, "\nCannot open the input file %s\n", input_filename);
           exit(-1);
        }
    }
    else
    {
        fprintf(stderr, "\nNo file names given\n");
        help();
        exit(-1);
    }

    if (argc > optind && argc-optind > 1)
    {
        output_filename = strdup(argv[optind+1]);
        fprintf(stderr, "\nOutput filename: %s\n", output_filename);
        if (!(output_file = fopen(output_filename, "wb")))
        {
            fprintf(stderr, "\nCannot open the output file %s\n", output_filename);
            exit(-1);
        }

    }
     else
     {
        output_file = stdout;
        follow_flag = 1;
        fprintf(stderr, "\nOutput filename: Standard output\n");
     }

}






int
main(int argc, char *argv[])
{
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    parse_options(argc, argv);

    write_file_header();
  
    switch(parser_type)
    {
    case MONITOR_YY:
        yyin = input_file;
        yylex();
        break;
    case DPDUMPGX_DPD:
        gettimeofday(&start_time_dpd, NULL); 
        dpdin = input_file;
        dpdlex();
        break;
    }
         
    return 0;
}
