#include <arpa/inet.h>  /* for ntohl() */
#include "sqlite3.h"
#include "output.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "out-record.h"
#include "string_s.h"
#include "crypto-base64.h"

enum STMT_ID_e {
	STMT_INIT = 0,
	STMT_NEW_SCAN,
	STMT_ADD_SENSE,
	STMT_SET_SCAN_TIMES,
};

struct db_stmt_s {
	enum STMT_ID_e id;
	const char *sqltext;
	sqlite3_stmt *stmt;
} stmts[] = {
	{
		.id = STMT_INIT,
		.sqltext =
		R"STATEMENT(
			PRAGMA journal_mode=WAL;
			CREATE TABLE IF NOT EXISTS sense (
				sense_id INTEGER PRIMARY KEY,
				scan_id,
				time,
				ip,
				ip_proto,
				port,
				ttl,
				proto,
				px
			);
			CREATE TABLE IF NOT EXISTS scans(
				scan_id INTEGER PRIMARY KEY,
				version,
				station,
				start,
				end,
				filename
			);
		)STATEMENT",
	},
	{
		.id = STMT_NEW_SCAN,
		.sqltext = "INSERT INTO scans(version, station, filename) VALUES(:version, :station, :filename);",
	},
	{
		.id = STMT_ADD_SENSE,
		.sqltext = R"STATEMENT(
			INSERT INTO sense(
				scan_id,
				time,
				ip,
				ip_proto,
				port,
				ttl,
				proto,
				px)
			VALUES(
				:scan_id,
				:time,
				:ip,
				:ip_proto,
				:port,
				:ttl,
				:proto,
				:px
			);
		)STATEMENT",
	},
	{
		.id = STMT_SET_SCAN_TIMES,
		.sqltext = "UPDATE scans SET start=:start, end=:end WHERE scan_id=:scan_id;",
	},
	{
		// sentinel
		.sqltext = NULL,
	}
};


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
	__label__ out_return;
	int rc;
	char *zErr = NULL;
	char *zErr2 = NULL;

	out->is_first_record_seen = 0;

	rc = sqlite3_config(SQLITE_CONFIG_URI, 0);
	if (rc != SQLITE_OK) {
		zErr = "couldn't config to disable URI support";
		goto out_return;
	}

	rc = sqlite3_open_v2(out->filename, &out->sqlite.db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
	if (rc != SQLITE_OK) {
		zErr = "in sqlite3_open";
		goto out_return;
	}

	// exec the init statement
	rc = sqlite3_exec(
		out->sqlite.db,
		stmts[0].sqltext,
		NULL,
		NULL,
		&zErr2
	);
	if (rc != SQLITE_OK) {
		zErr = "while executing init statement: ";
		goto out_return;
	}

	for (enum STMT_ID_e i = 0; stmts[i].sqltext; i++) {
		rc = sqlite3_prepare_v2(
			out->sqlite.db,
			stmts[i].sqltext,
			-1,
			&stmts[i].stmt,
			NULL
		);
		if (rc != SQLITE_OK) {
			zErr = "in prepare";
			goto out_return;
		}
	}

	// add row to scans table to get scan_id. we will fill in other info later
	struct db_stmt_s *s = &stmts[STMT_NEW_SCAN];

	// scan version
	rc = sqlite3_bind_int(s->stmt, 1, 0);
	if (rc != SQLITE_OK) {
		zErr = "in new scan bind version";
		goto out_return;
	}

	// scan station
	rc = sqlite3_bind_null(s->stmt, 2);
	if (rc != SQLITE_OK) {
		zErr = "in new scan bind station";
		goto out_return;
	}

	// scan filename
	rc = sqlite3_bind_null(s->stmt, 3);
	if (rc != SQLITE_OK) {
		zErr = "in new scan bind filename";
		goto out_return;
	}

	// step the statement
	rc = sqlite3_step(s->stmt);
	if (rc != SQLITE_DONE) {
		zErr = "in new scan step";
		goto out_return;
	}

	// retrieve the scan_id, which is the rowid of the last insert
	out->sqlite.scan_id = sqlite3_last_insert_rowid(out->sqlite.db);

	// reset and clear binds on previous statement
	rc = sqlite3_reset(s->stmt);
	if (rc != SQLITE_OK) {
		zErr = "in new scan reset";
		goto out_return;
	}
	rc = sqlite3_clear_bindings(s->stmt);
	// fun fact, the return value of sqlite3_clear_bindings is not
	// defined in the sqlite documentation.
	

	// begin a transaction
	rc = sqlite3_exec(
		out->sqlite.db,
		"BEGIN;",
		NULL,
		NULL,
		NULL
	);
	if (rc != SQLITE_OK) {
		zErr = "beginning transaction";
		goto out_return;
	}

out_return:
	if (zErr) {
		fprintf(stderr, "%s: error: %s%s\n",
			__FUNCTION__,
			zErr,
			zErr2?:""
		);
		if (zErr2) sqlite3_free(zErr2);
		exit(1);
	}
}


/****************************************************************************
 ****************************************************************************/
static void
sqlite_out_close(struct Output *out, FILE *fp)
{
	__label__ out_return;
	int rc;
	char *zErr = NULL;

	// set scan start/end times
	struct db_stmt_s *s = &stmts[STMT_SET_SCAN_TIMES];

	// bind start time
	rc = sqlite3_bind_int64(
		s->stmt,
		1,
		out->sqlite.t_min
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind start time";
		goto out_return;
	}

	// bind end time
	rc = sqlite3_bind_int64(
		s->stmt,
		2,
		out->sqlite.t_max
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind end time";
		goto out_return;
	}

	// bind scan_id
	rc = sqlite3_bind_int64(
		s->stmt,
		3,
		out->sqlite.scan_id
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind scan_id";
		goto out_return;
	}

	// step statement
	rc = sqlite3_step(s->stmt);
	if (rc != SQLITE_DONE) {
		zErr = "in step";
		goto out_return;
	}

	rc = sqlite3_reset(s->stmt);
	if (rc != SQLITE_OK) {
		zErr = "in reset";
		goto out_return;
	}
	rc = sqlite3_clear_bindings(s->stmt);

	// commit transaction
	rc = sqlite3_exec(
		out->sqlite.db,
		"COMMIT;",
		NULL,
		NULL,
		NULL
	);
	if (rc != SQLITE_OK) {
		zErr = "commiting transaction";
		goto out_return;
	}

out_return:
	if (zErr) {
		fprintf(stderr, "%s: error: %s\n",
			__FUNCTION__,
			zErr
		);
		exit(1);
	}
}

/****************************************************************************
 ****************************************************************************/
static void
sqlite_out_status(struct Output *out, FILE *fp, time_t timestamp,
    int status, unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
	__label__ out_return;
	int rc;
	char *zErr = NULL;

	struct db_stmt_s *s = &stmts[STMT_ADD_SENSE];

	// update min/max observed times for this scan
	if (!out->is_first_record_seen) {
		out->is_first_record_seen = 1;
		out->sqlite.t_min = timestamp;
		out->sqlite.t_max = timestamp;
	} else {
		if (timestamp < out->sqlite.t_min)
			out->sqlite.t_min = timestamp;
		if (timestamp > out->sqlite.t_max)
			out->sqlite.t_max = timestamp;
	}

	// bind all the things...
	rc = sqlite3_bind_int(
		s->stmt,
		1,
		out->sqlite.scan_id
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind scan_id";
		goto out_return;
	}

	rc = sqlite3_bind_int64(
		s->stmt,
		2,
		timestamp
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind timestamp";
		goto out_return;
	}

	rc = sqlite3_bind_int64(
		s->stmt,
		3,
		ip
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind ip";
		goto out_return;
	}

	rc = sqlite3_bind_int(
		s->stmt,
		4,
		ip_proto
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind ip_proto";
		goto out_return;
	}

	rc = sqlite3_bind_int(
		s->stmt,
		5,
		port
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind port";
		goto out_return;
	}

	rc = sqlite3_bind_int(
		s->stmt,
		6,
		ttl
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind ttl";
		goto out_return;
	}

	char reason_buffer[128];
	reason_string(reason, reason_buffer, sizeof(reason_buffer));

	rc = sqlite3_bind_text(
		s->stmt,
		7,
		reason_buffer,
		-1,
		SQLITE_STATIC
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind proto";
		goto out_return;
	}

	// bind px = null
	rc = sqlite3_bind_null(
		s->stmt,
		8
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind px (null)";
		goto out_return;
	}

	// step the statement
	rc = sqlite3_step(s->stmt);
	if (rc != SQLITE_DONE) {
		zErr = "in step";
		goto out_return;
	}

	// reset and clear binds
	rc = sqlite3_reset(s->stmt);
	if (rc != SQLITE_OK) {
		zErr = "in reset";
		goto out_return;
	}
	rc = sqlite3_clear_bindings(s->stmt);

out_return:
	if (zErr) {
		fprintf(stderr, "%s: error: %s\n",
			__FUNCTION__,
			zErr
		);
	}
}


/****************************************************************************
 ****************************************************************************/
static void
sqlite_out_banner(struct Output *out, FILE *fp, time_t timestamp,
        unsigned ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, unsigned ttl,
        const unsigned char *px, unsigned length)
{
	__label__ out_return;
	int rc;
	char *zErr = NULL;

	struct db_stmt_s *s = &stmts[STMT_ADD_SENSE];

	// update min/max observed times for this scan
	if (!out->is_first_record_seen) {
		out->is_first_record_seen = 1;
		out->sqlite.t_min = timestamp;
		out->sqlite.t_max = timestamp;
	} else {
		if (timestamp < out->sqlite.t_min)
			out->sqlite.t_min = timestamp;
		if (timestamp > out->sqlite.t_max)
			out->sqlite.t_max = timestamp;
	}

	// bind all the things...
	rc = sqlite3_bind_int(
		s->stmt,
		1,
		out->sqlite.scan_id
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind scan_id";
		goto out_return;
	}

	rc = sqlite3_bind_int64(
		s->stmt,
		2,
		timestamp
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind timestamp";
		goto out_return;
	}

	rc = sqlite3_bind_int64(
		s->stmt,
		3,
		ip
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind ip";
		goto out_return;
	}

	rc = sqlite3_bind_int(
		s->stmt,
		4,
		ip_proto
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind ip_proto";
		goto out_return;
	}

	rc = sqlite3_bind_int(
		s->stmt,
		5,
		port
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind port";
		goto out_return;
	}

	rc = sqlite3_bind_int(
		s->stmt,
		6,
		ttl
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind ttl";
		goto out_return;
	}

	rc = sqlite3_bind_text(
		s->stmt,
		7,
		masscan_app_to_string(proto),
		-1,
		SQLITE_STATIC
	);
	if (rc != SQLITE_OK) {
		zErr = "in bind proto";
		goto out_return;
	}

	// for px we need some extra logic.
	// sometimes the px field comes to us base64-encoded. we want to
	// undo that.
	
	switch(proto) {
	case PROTO_X509_CERT:
	case PROTO_UDP_ZEROACCESS:
	{
		uint8_t *pxbuf = NULL;
		size_t pxbuf_len = 0;

		//pxbuf_len = length;
		pxbuf_len = 0;
		pxbuf = malloc(pxbuf_len);
		if (!pxbuf) {
			zErr = "allocating pxbuf";
			goto out_return;
		}
		if (pxbuf_len != 0)
			pxbuf_len = base64_decode(pxbuf, length, px, length);
		if (pxbuf_len == 0) {
			rc = sqlite3_bind_null(
				s->stmt,
				8
			);
		} else {
			if (!pxbuf) {
				zErr = "reallocating pxbuf";
				goto out_return;
			}

			rc = sqlite3_bind_blob(
				s->stmt,
				8,
				pxbuf,
				pxbuf_len,
				free
			);
		}
		if (rc != SQLITE_OK) {
			zErr = "in bind px";
			goto out_return;
		}
	}
		break;
	default:
		rc = sqlite3_bind_text(
			s->stmt,
			8,
			(const char *)px,
			length,
			SQLITE_TRANSIENT
		);
		if (rc != SQLITE_OK) {
			zErr = "in bind px";
			goto out_return;
		}
		break;
	}

	// step the statement
	rc = sqlite3_step(s->stmt);
	if (rc != SQLITE_DONE) {
		zErr = "in step";
		goto out_return;
	}

	// reset and clear binds
	rc = sqlite3_reset(s->stmt);
	if (rc != SQLITE_OK) {
		zErr = "in reset";
		goto out_return;
	}
	rc = sqlite3_clear_bindings(s->stmt);

out_return:
	if (zErr) {
		fprintf(stderr, "%s: error: %s\n",
			__FUNCTION__,
			zErr
		);
	}
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


