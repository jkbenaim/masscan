#include <arpa/inet.h>  /* for ntohl() */
#include "output.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "out-record.h"
#include "string_s.h"

/****************************************************************************
 ****************************************************************************/
static void
*sqlite_out_create(struct Output *out)
{
    /* TODO */
    return NULL;
}

/****************************************************************************
 ****************************************************************************/
static void
sqlite_out_open(struct Output *out, FILE *fp)
{
    
    
//     sqlite_out_banner(struct Output *out, FILE *fp, time_t timestamp,
//                       unsigned ip, unsigned ip_proto, unsigned port,
//                       enum ApplicationProtocol proto, unsigned ttl,
//                       const unsigned char *px, unsigned length)
    fprintf(fp,
        "PRAGMA jorunal_mode=WAL;\n"
        "CREATE TABLE IF NOT EXISTS status(\n"
        "    time INTEGER,\n"
        "    status TEXT,\n"
        "    ip TEXT,\n"
        "    ip_proto TEXT,\n"
        "    port INTEGER,\n"
        "    reason TEXT,\n"
        "    ttl INTEGER\n"
        ");\n"
        "CREATE TABLE IF NOT EXISTS banners(\n"
        "    time INTEGER,\n"
        "    ip TEXT,\n"
        "    ip_proto INTEGER,\n"
        "    port INTEGER,\n"
        "    proto TEXT,\n"
        "    ttl INTEGER,\n"
        "    px TEXT\n"
        ");\n"
//         "BEGIN;\n"
    );
}


/****************************************************************************
 ****************************************************************************/
static void
sqlite_out_close(struct Output *out, FILE *fp)
{
//     fprintf(fp, "END;\n");
}

/****************************************************************************
 ****************************************************************************/
static void
sqlite_out_status(struct Output *out, FILE *fp, time_t timestamp,
    int status, unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    uint8_t ip_bytes[4];
    char ip_string[16];
    ip = htonl(ip);
    memcpy(&ip_bytes, &ip, 4);
    
    char reason_buffer[128];
    
    reason_string(reason, reason_buffer, sizeof(reason_buffer)),
    snprintf((char *)&ip_string, 16, "%u.%u.%u.%u", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
    fprintf(fp, "INSERT INTO status VALUES(%ld, \"%s\", \"%s\", \"%s\", %u, \"%s\",%u);\n",
            timestamp,
            status_string(status),
            ip_string,
            name_from_ip_proto(ip_proto),
            port,
            reason_buffer,
            ttl
    );
}


/****************************************************************************
 ****************************************************************************/
static void
sqlite_out_banner(struct Output *out, FILE *fp, time_t timestamp,
        unsigned ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, unsigned ttl,
        const unsigned char *px, unsigned length)
{
    uint8_t ip_bytes[4];
    char ip_string[16];
    ip = htonl(ip);
    memcpy(&ip_bytes, &ip, 4);
    snprintf((char *)&ip_string, 16, "%u.%u.%u.%u", ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
    char banner_buffer[4096];
    
    fprintf(fp, "INSERT INTO banners VALUES(%ld, \"%s\", \"%s\", %d, \"%s\", %d, \"%s\");\n",
            timestamp,
            ip_string,
            name_from_ip_proto(ip_proto),
            port,
            masscan_app_to_string(proto),
            ttl,
            normalize_string(px, length, banner_buffer, sizeof(banner_buffer))
    );
}


/****************************************************************************
 ****************************************************************************/
const struct OutputType sqlite_output = {
    "sql",
    sqlite_out_create,
    sqlite_out_open,
    sqlite_out_close,
    sqlite_out_status,
    sqlite_out_banner,
};


