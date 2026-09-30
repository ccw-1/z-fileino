/*
 * z-fileinfo.c — Query file information on a remote z/OS (USS) system over SSH.
 *
 * Uses only commands available in the BCP (Basic Control Program) USS
 * environment — no extra packages required on the z/OS side.
 *
 * Usage:
 *   z-fileinfo [user@]host <filepath>              # /bin/file output
 *   z-fileinfo [user@]host -ls  <filepath>         # ls -la
 *   z-fileinfo [user@]host -stat <filepath>        # stat(1)
 *   z-fileinfo [user@]host -od <filepath>          # first 32 bytes hex dump
 *   z-fileinfo [user@]host -all <filepath>         # all of the above
 *   z-fileinfo -help                               # this message
 *   z-fileinfo -version                            # version string
 *
 * MCP mode: invoked as z-fileinfo-mcp (or --mcp flag).
 *
 * Build: gcc -std=c11 -Wall -Wextra -O2 -o z-fileinfo z-fileinfo.c
 */

#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define VERSION "0.1.0"
#define PROG    "z-fileinfo"

/* -------------------------------------------------------------------------
 * Buffer helpers (shared with MCP layer)
 * ---------------------------------------------------------------------- */

typedef struct { char *data; size_t len, cap; } Buf;

static void buf_init(Buf *b) {
    b->cap = 4096; b->len = 0;
    b->data = malloc(b->cap);
    if (b->data) b->data[0] = '\0';
}
static void buf_free(Buf *b) { free(b->data); b->data = NULL; b->len = b->cap = 0; }
static void buf_reserve(Buf *b, size_t extra) {
    while (b->len + extra + 1 > b->cap) {
        b->cap *= 2;
        b->data = realloc(b->data, b->cap);
    }
}
static void buf_append(Buf *b, const char *s) {
    size_t n = strlen(s);
    buf_reserve(b, n);
    memcpy(b->data + b->len, s, n + 1);
    b->len += n;
}
static void buf_appendn(Buf *b, const char *s, size_t n) {
    buf_reserve(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = '\0';
}
static void buf_append_escaped(Buf *b, const char *src) {
    static const char *hexd = "0123456789abcdef";
    for (; *src; src++) {
        unsigned char c = (unsigned char)*src;
        switch (c) {
        case '"':  buf_append(b, "\\\""); break;
        case '\\': buf_append(b, "\\\\"); break;
        case '\n': buf_append(b, "\\n");  break;
        case '\r': buf_append(b, "\\r");  break;
        case '\t': buf_append(b, "\\t");  break;
        default:
            if (c < 0x20) {
                char u[7]; u[0]='\\'; u[1]='u'; u[2]='0'; u[3]='0';
                u[4]=hexd[(c>>4)&0xf]; u[5]=hexd[c&0xf]; u[6]='\0';
                buf_append(b, u);
            } else {
                buf_reserve(b, 1);
                b->data[b->len++] = (char)c;
                b->data[b->len] = '\0';
            }
        }
    }
}

/* -------------------------------------------------------------------------
 * SSH runner
 * Run: ssh <target> <remote_cmd>, capture combined stdout+stderr.
 * Returns exit code, or -1 on spawn failure.
 * ---------------------------------------------------------------------- */

static int ssh_run(const char *target, const char *remote_cmd, Buf *out) {
    int pipefd[2];
    if (pipe(pipefd)) {
        buf_append(out, "pipe() failed: ");
        buf_append(out, strerror(errno));
        return -1;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]); close(pipefd[1]);
        buf_append(out, "fork() failed: ");
        buf_append(out, strerror(errno));
        return -1;
    }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execlp("ssh", "ssh", "-o", "BatchMode=yes",
               "-o", "ConnectTimeout=10",
               target, remote_cmd, (char *)NULL);
        fprintf(stderr, "execlp(ssh) failed: %s\n", strerror(errno));
        _exit(127);
    }
    close(pipefd[1]);
    char chunk[4096]; ssize_t nr;
    while ((nr = read(pipefd[0], chunk, sizeof(chunk))) > 0)
        buf_appendn(out, chunk, (size_t)nr);
    close(pipefd[0]);
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR);
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}

/* -------------------------------------------------------------------------
 * Core query functions — each issues one SSH command.
 * ---------------------------------------------------------------------- */

/* /bin/file <filepath> — file type identification */
static int query_file(const char *target, const char *filepath, Buf *out) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "/bin/file '%s' 2>&1", filepath);
    return ssh_run(target, cmd, out);
}

/* ls -la <filepath> */
static int query_ls(const char *target, const char *filepath, Buf *out) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "ls -la '%s' 2>&1", filepath);
    return ssh_run(target, cmd, out);
}

/* ls -laT <filepath> — detailed listing with z/OS file tag (CCSID, T=on/off) */
static int query_stat(const char *target, const char *filepath, Buf *out) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd), "ls -laT '%s' 2>&1", filepath);
    return ssh_run(target, cmd, out);
}

/* /bin/od -A x -t x1 -N 32 <filepath> — first 32 bytes hex dump (POSIX od) */
static int query_od(const char *target, const char *filepath, Buf *out) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
             "/bin/od -A x -t x1 -N 32 '%s' 2>&1", filepath);
    return ssh_run(target, cmd, out);
}

/* All four queries combined */
static int query_all(const char *target, const char *filepath, Buf *out) {
    char cmd[4096];
    snprintf(cmd, sizeof(cmd),
             "echo '=== /bin/file ===' && /bin/file '%s' 2>&1 ; "
             "echo '=== ls -la ===' && ls -la '%s' 2>&1 ; "
             "echo '=== ls -laT (tag) ===' && ls -laT '%s' 2>&1 ; "
             "echo '=== od (first 32 bytes) ===' && /bin/od -A x -t x1 -N 32 '%s' 2>&1",
             filepath, filepath, filepath, filepath);
    return ssh_run(target, cmd, out);
}

/* -------------------------------------------------------------------------
 * CLI entry point
 * ---------------------------------------------------------------------- */

static void usage(void) {
    fprintf(stderr,
        PROG " " VERSION "\n"
        "\n"
        "Query file information on a remote z/OS USS system over SSH.\n"
        "Uses only BCP-standard commands — no extra packages required on z/OS.\n"
        "\n"
        "Usage:\n"
        "  " PROG " [user@]host <filepath>          /bin/file (default)\n"
        "  " PROG " [user@]host -ls   <filepath>    ls -la\n"
        "  " PROG " [user@]host -stat <filepath>    ls -laT (tag info)\n"
        "  " PROG " [user@]host -od   <filepath>    /bin/od hex dump (first 32 bytes)\n"
        "  " PROG " [user@]host -all  <filepath>    all of the above\n"
        "  " PROG " -help                           show this message\n"
        "  " PROG " -version                        print version\n"
        "\n"
        "MCP server mode:\n"
        "  " PROG "-mcp     (invoked as z-fileinfo-mcp)\n"
        "  " PROG " --mcp   (explicit flag)\n"
        "\n"
        "Examples:\n"
        "  " PROG " pok56 /u/ccw/hello\n"
        "  " PROG " ccw@pok56 -all /u/ccw/hello\n"
        "  " PROG " pok56 -ls /usr/bin\n"
    );
}

/* forward declaration — defined below after JSON helpers */
static void run_mcp(void);

int main(int argc, char **argv) {
    /* MCP mode: invoked as z-fileinfo-mcp or --mcp */
    {
        const char *base = strrchr(argv[0], '/');
        base = base ? base + 1 : argv[0];
        if (strcmp(base, PROG "-mcp") == 0) { run_mcp(); return 0; }
    }
    if (argc >= 2 && strcmp(argv[1], "--mcp") == 0) { run_mcp(); return 0; }

    if (argc < 2 || strcmp(argv[1], "-help") == 0 ||
                    strcmp(argv[1], "--help") == 0 ||
                    strcmp(argv[1], "-h") == 0) {
        usage(); return 0;
    }
    if (strcmp(argv[1], "-version") == 0 ||
        strcmp(argv[1], "--version") == 0) {
        printf(PROG " " VERSION "\n"); return 0;
    }

    /* Normal mode: <target> [-mode] <filepath> */
    if (argc < 3) { usage(); return 1; }

    const char *target   = argv[1];
    const char *mode     = "-file";
    const char *filepath = NULL;

    if (argc == 3) {
        /* z-fileinfo host filepath  →  default /bin/file */
        filepath = argv[2];
    } else if (argc == 4) {
        mode     = argv[2];
        filepath = argv[3];
    } else {
        usage(); return 1;
    }

    Buf out; buf_init(&out);
    int rc = 0;

    if (strcmp(mode, "-file") == 0 || strcmp(mode, "--file") == 0) {
        rc = query_file(target, filepath, &out);
    } else if (strcmp(mode, "-ls") == 0 || strcmp(mode, "--ls") == 0) {
        rc = query_ls(target, filepath, &out);
    } else if (strcmp(mode, "-stat") == 0 || strcmp(mode, "--stat") == 0) {
        rc = query_stat(target, filepath, &out);
    } else if (strcmp(mode, "-od") == 0 || strcmp(mode, "--od") == 0) {
        rc = query_od(target, filepath, &out);
    } else if (strcmp(mode, "-all") == 0 || strcmp(mode, "--all") == 0) {
        rc = query_all(target, filepath, &out);
    } else {
        fprintf(stderr, PROG ": unknown mode '%s'\n\n", mode);
        usage();
        buf_free(&out);
        return 1;
    }

    if (out.len > 0) fputs(out.data, stdout);
    buf_free(&out);
    return rc;
}

/* =========================================================================
 * MCP server — stdio JSON-RPC 2.0
 * ====================================================================== */

/* --- minimal JSON helpers -------------------------------------------- */

static int json_get_string(const char *json, const char *key,
                            char *out, size_t outsz) {
    char needle[160];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return 0;
    p += strlen(needle);
    while (*p && (*p==' '||*p=='\t'||*p=='\n'||*p=='\r'||*p==':')) p++;
    if (*p == 'n' && strncmp(p,"null",4)==0) return 0;
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i+1 < outsz) {
        if (*p == '\\') {
            p++;
            switch (*p) {
            case '"': case '\\': case '/': out[i++]=*p; break;
            case 'n': out[i++]='\n'; break;
            case 'r': out[i++]='\r'; break;
            case 't': out[i++]='\t'; break;
            case '\0': goto done;
            default: out[i++]=*p; break;
            }
        } else { out[i++]=*p; }
        p++;
    }
done:
    out[i]='\0'; return 1;
}

static void json_get_id(const char *json, char *out, size_t outsz) {
    const char *p = strstr(json, "\"id\"");
    if (!p) { snprintf(out,outsz,"null"); return; }
    p += 4;
    while (*p && (*p==' '||*p=='\t'||*p==':')) p++;
    if (!*p) { snprintf(out,outsz,"null"); return; }
    size_t i = 0;
    if (*p == '"') {
        out[i++] = *p++;
        while (*p && i+1 < outsz) {
            if (*p=='\\') { out[i++]=*p++; if(*p&&i+1<outsz) out[i++]=*p++; continue; }
            out[i++]=*p; if (*p++=='"') break;
        }
        out[i]='\0'; return;
    }
    while (*p && i+1 < outsz) {
        if (*p==','||*p=='}'||*p==']'||*p==' '||*p=='\t'||*p=='\n'||*p=='\r') break;
        out[i++]=*p++;
    }
    out[i]='\0';
    if (!i) snprintf(out,outsz,"null");
}

static const char *find_arguments(const char *req) {
    const char *params = strstr(req, "\"params\"");
    if (!params) return NULL;
    const char *a = strstr(params, "\"arguments\"");
    if (!a) return NULL;
    return strchr(a, '{');
}

/* --- response builders ----------------------------------------------- */

static void send_line(const char *json) { fputs(json,stdout); fputc('\n',stdout); fflush(stdout); }

static void send_error(const char *id, int code, const char *msg) {
    Buf b; buf_init(&b);
    buf_append(&b, "{\"jsonrpc\":\"2.0\",\"id\":"); buf_append(&b, id);
    buf_append(&b, ",\"error\":{\"code\":"); char cb[32]; snprintf(cb,sizeof(cb),"%d",code);
    buf_append(&b, cb); buf_append(&b, ",\"message\":\"");
    buf_append_escaped(&b, msg); buf_append(&b, "\"}}");
    send_line(b.data); buf_free(&b);
}

static void send_result(const char *id, const char *result_json) {
    Buf b; buf_init(&b);
    buf_append(&b, "{\"jsonrpc\":\"2.0\",\"id\":"); buf_append(&b, id);
    buf_append(&b, ",\"result\":"); buf_append(&b, result_json); buf_append(&b, "}");
    send_line(b.data); buf_free(&b);
}

static void tool_result(const char *id, const char *text, int is_error) {
    Buf r; buf_init(&r);
    buf_append(&r, "{\"content\":[{\"type\":\"text\",\"text\":\"");
    buf_append_escaped(&r, text);
    buf_append(&r, "\"}]");
    if (is_error) buf_append(&r, ",\"isError\":true");
    buf_append(&r, "}");
    send_result(id, r.data); buf_free(&r);
}

/* --- tool handlers --------------------------------------------------- */

#define MCP_NAME    "z-fileinfo-mcp"
#define MCP_VERSION VERSION

static void mcp_handle_initialize(const char *id) {
    send_result(id,
        "{"
          "\"protocolVersion\":\"2024-11-05\","
          "\"capabilities\":{\"tools\":{}},"
          "\"serverInfo\":{\"name\":\"" MCP_NAME "\","
                          "\"version\":\"" MCP_VERSION "\"}"
        "}");
}

static void mcp_handle_tools_list(const char *id) {
    send_result(id,
        "{"
          "\"tools\":["
            "{"
              "\"name\":\"z_fileinfo_query\","
              "\"description\":\"Query file information on a remote z/OS USS system over SSH using BCP-standard commands only. "
                "Supports /bin/file identification, ls -la listing, stat(1) metadata, /bin/od hex dump of first 32 bytes, or all four combined.\","
              "\"inputSchema\":{"
                "\"type\":\"object\","
                "\"properties\":{"
                  "\"target\":{\"type\":\"string\","
                    "\"description\":\"SSH target in [user@]host form (e.g. pok56 or ccw@pok56). Must be reachable via ssh BatchMode=yes.\"},"
                  "\"filepath\":{\"type\":\"string\","
                    "\"description\":\"Absolute or relative path of the file to inspect on the remote z/OS system.\"},"
                  "\"mode\":{\"type\":\"string\","
                    "\"description\":\"Query mode: file (default) | ls | stat | od | all\","
                    "\"enum\":[\"file\",\"ls\",\"stat\",\"od\",\"all\"]}"
                "},"
                "\"required\":[\"target\",\"filepath\"]"
              "}"
            "},"
            "{"
              "\"name\":\"z_fileinfo_help\","
              "\"description\":\"Return z-fileinfo usage, available modes, and examples.\","
              "\"inputSchema\":{\"type\":\"object\",\"properties\":{}}"
            "}"
          "]"
        "}");
}

static void mcp_handle_query(const char *id, const char *args) {
    char target[256] = {0}, filepath[4096] = {0}, mode[32] = "file";
    json_get_string(args, "target",   target,   sizeof(target));
    json_get_string(args, "filepath", filepath, sizeof(filepath));
    json_get_string(args, "mode",     mode,     sizeof(mode));

    if (!target[0]) { send_error(id, -32602, "target is required"); return; }
    if (!filepath[0]) { send_error(id, -32602, "filepath is required"); return; }

    Buf out; buf_init(&out);
    int rc = 0;

    if (strcmp(mode,"file")==0)      rc = query_file (target, filepath, &out);
    else if (strcmp(mode,"ls")==0)   rc = query_ls   (target, filepath, &out);
    else if (strcmp(mode,"stat")==0) rc = query_stat (target, filepath, &out);
    else if (strcmp(mode,"od")==0)   rc = query_od   (target, filepath, &out);
    else if (strcmp(mode,"all")==0)  rc = query_all  (target, filepath, &out);
    else {
        char msg[128];
        snprintf(msg,sizeof(msg),"unknown mode '%s'; use file|ls|stat|od|all", mode);
        send_error(id,-32602,msg);
        buf_free(&out); return;
    }

    Buf txt; buf_init(&txt);
    char head[512];
    snprintf(head,sizeof(head),
             "target: %s\nfilepath: %s\nmode: %s\nexit_code: %d\n\n",
             target, filepath, mode, rc);
    buf_append(&txt, head);
    if (out.len > 0) buf_append(&txt, out.data);
    tool_result(id, txt.data, rc != 0);
    buf_free(&out); buf_free(&txt);
}

static void mcp_handle_help(const char *id) {
    tool_result(id,
        "z-fileinfo — file information queries on remote z/OS USS via SSH.\n"
        "\n"
        "Uses only BCP-standard commands (no extra packages on z/OS):\n"
        "  file  /bin/file <filepath>                    — file type identification\n"
        "  ls    ls -la <filepath>                       — detailed directory listing\n"
        "  stat  ls -laT <filepath>                     — listing with z/OS tag (CCSID, T=on/off)\n"
        "  od    /bin/od -A x -t x1 -N 32 <filepath>   — first 32 bytes hex dump (POSIX od)\n"
        "  all   all four commands combined\n"
        "\n"
        "MCP tool: z_fileinfo_query(target, filepath, mode)\n"
        "  target   : [user@]host  (e.g. pok56 or ccw@pok56)\n"
        "  filepath : path on the remote z/OS system\n"
        "  mode     : file (default) | ls | stat | od | all\n"
        "\n"
        "Examples:\n"
        "  z_fileinfo_query(target='pok56', filepath='/u/ccw/hello')\n"
        "  z_fileinfo_query(target='pok56', filepath='/u/ccw/hello', mode='all')\n"
        "  z_fileinfo_query(target='ccw@pok56', filepath='/usr/bin', mode='ls')\n",
        0);
}

static void mcp_handle_tools_call(const char *id, const char *req) {
    const char *args = find_arguments(req);
    char name[64] = {0};
    const char *params = strstr(req, "\"params\"");
    if (params) json_get_string(params, "name", name, sizeof(name));
    if (!name[0]) { send_error(id,-32602,"missing tool name"); return; }
    char empty[] = "{}";
    if (!args) args = empty;

    if (strcmp(name,"z_fileinfo_query")==0) mcp_handle_query(id, args);
    else if (strcmp(name,"z_fileinfo_help")==0) mcp_handle_help(id);
    else {
        char msg[128]; snprintf(msg,sizeof(msg),"unknown tool: %s",name);
        send_error(id,-32601,msg);
    }
}

static void mcp_dispatch(const char *line) {
    char method[128]={0}, id[128]={0};
    json_get_id(line, id, sizeof(id));
    json_get_string(line, "method", method, sizeof(method));
    int has_id = (strstr(line,"\"id\"") != NULL);
    if (!has_id) { fprintf(stderr, MCP_NAME ": notification: %s\n", method); return; }

    if      (strcmp(method,"initialize")==0)  mcp_handle_initialize(id);
    else if (strcmp(method,"tools/list")==0)  mcp_handle_tools_list(id);
    else if (strcmp(method,"tools/call")==0)  mcp_handle_tools_call(id, line);
    else if (strcmp(method,"ping")==0)        send_result(id, "{}");
    else {
        char msg[192]; snprintf(msg,sizeof(msg),"method not found: %s",method[0]?method:"(none)");
        send_error(id,-32601,msg);
    }
}

static void run_mcp(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    fprintf(stderr, MCP_NAME " " MCP_VERSION " running on stdio\n");
    char  *line = NULL; size_t cap = 0; ssize_t n;
    while ((n = getline(&line, &cap, stdin)) > 0) {
        if (n > 0 && line[n-1]=='\n') line[n-1]='\0';
        if (line[0]=='\0') continue;
        mcp_dispatch(line);
    }
    free(line);
    fprintf(stderr, MCP_NAME ": stdin closed, exiting\n");
}
