#include <arpa/inet.h>  /* for ntohl() */
#include "output.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "out-record.h"
#include "string_s.h"

static void sqlite_out_tr_end(struct Output *out, FILE *fp)
{
	if(out->sqlite.in_transaction) {
		fprintf(fp, "END;\n");
		out->sqlite.in_transaction = 0;
	}
}

static void sqlite_out_tr_continue(struct Output *out, FILE *fp, unsigned rows)
{
	if((out->sqlite.rows_this_transaction >= out->sqlite.rows_per_transaction)
		&& out->sqlite.in_transaction) {
		fprintf(fp, "END;\n");
		out->sqlite.rows_this_transaction = 0;
		out->sqlite.in_transaction = 0;
	}
	if(!out->sqlite.in_transaction) {
		fprintf(fp, "BEGIN;\n");
		out->sqlite.in_transaction = 1;
	}
	out->sqlite.rows_this_transaction += rows;
}

/****************************************************************************
 ****************************************************************************/
static void
*sqlite_out_create(struct Output *out)
{
    return NULL;
}

/****************************************************************************
 ****************************************************************************/
static void
sqlite_out_open(struct Output *out, FILE *fp)
{
	out->sqlite.in_transaction = 0;
	out->sqlite.rows_per_transaction = 100000;
	out->sqlite.rows_this_transaction = 0;

	fprintf(fp,
		"PRAGMA jorunal_mode=WAL;\n"
		"DROP TABLE IF EXISTS temp.vars;\n"
		"CREATE TABLE temp.vars(\n"
		"    key TEXT UNIQUE,\n"
		"    val\n"
		");\n"
		"CREATE TABLE IF NOT EXISTS sense(\n"
		"    sense_id INTEGER PRIMARY KEY,\n"
		"    scan_id INT,\n"
		"    time INT,\n"
		"    ip INT,\n"
		"    ip_proto INT,\n"
		"    port INT,\n"
		"    ttl INT,\n"
		"    proto TEXT,\n"
		"    px TEXT\n"
		");\n"
		"CREATE TABLE IF NOT EXISTS scans(\n"
		"    scan_id INTEGER PRIMARY KEY,\n"
		"    version INT,\n"
		"    station TEXT,\n"
		"    start INT,\n"
		"    end INT,\n"
		"    filename TEXT\n"
		");\n"
		"INSERT INTO scans(version) VALUES(0);\n"
		"INSERT INTO temp.vars(key,val) SELECT 'scan_id', last_insert_rowid();\n"

	);

	sqlite_out_tr_continue(out, fp, 0);
}


/****************************************************************************
 ****************************************************************************/
static void
sqlite_out_close(struct Output *out, FILE *fp)
{
	sqlite_out_tr_end(out, fp);
}

/****************************************************************************
 ****************************************************************************/
static void
sqlite_out_status(struct Output *out, FILE *fp, time_t timestamp,
    int status, unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    char reason_buffer[128];
    
    reason_string(reason, reason_buffer, sizeof(reason_buffer)),

    sqlite_out_tr_continue(out, fp, 1);

    fprintf(fp, "INSERT INTO sense(scan_id, time, ip, ip_proto, port, ttl, proto, px) SELECT val, %ld, %u, %u, %u, %u, '%s', null FROM temp.vars WHERE key=='scan_id';\n",
            timestamp,
            ip,
            ip_proto,
            port,
            ttl,
            reason_buffer
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
    char banner_buffer[131072];

    sqlite_out_tr_continue(out, fp, 1);
    
    fprintf(fp, "INSERT INTO sense(scan_id, time, ip, ip_proto, port, ttl, proto, px) SELECT val, %ld, %u, %u, %u, %u, '%s', '%s' FROM temp.vars WHERE key=='scan_id';\n",
            timestamp,
            ip,
            ip_proto,
            port,
            ttl,
            masscan_app_to_string(proto),
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


