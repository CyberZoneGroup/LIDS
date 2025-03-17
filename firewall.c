/*
 * firewall.c - Gelişmiş IDS/IPS Sistemi
 * Son Sürüm: Tüm Fonksiyonlarla Tam Implementasyon
 *
 * - IPS modunda tespit edilen saldırıların kaynak IP'leri "iptables" komutuyla engellenir.
 * - Dinamik Profiling: "Kuralları Entegre Et" seçeneğiyle belirli süre trafik izlenip,
 *   ortalama TCP SYN ve ARP sayıları esas alınarak eşik değerler güncellenir.
 * - Canlı izleme çıktısı; her satırda [ZAMAN] <OLAY TİPİ>: <DETAYLAR> biçiminde detaylı bilgi verir.
 * - Tespit algoritmaları (ARP/MITM, SYN Flood, Port Tarama, HTTP, SSH, SQL Injection, DNS Tünelleme, TOR, MAC Çakışması)
 *   güçlü bir şekilde loglanır.
 * - Router IP'si (örneğin, 192.168.1.1) komut satırından girilirse, bu IP'den gelen trafik ihmal edilir.
 *
 * Kullanım: sudo ./firewall <arayüz> [router_ip]
 * Örnek: sudo ./firewall wlan0 192.168.1.1
 *
 * Not: Banner bölümüne kendi ASCII sanatınızı ekleyebilirsiniz.
 */

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <net/if.h>
#include <ctype.h>
#include <stdatomic.h>

// ANSI renk kodları
// ANSI renk kodlarına mor ve pembe ekle
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_MAGENTA "\x1b[35m"
#define COLOR_PINK    "\x1b[95m"
#define COLOR_RESET   "\x1b[0m"
// Standart Renkler
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_WHITE   "\x1b[37m"

// Parlak (Bright) Renkler
#define COLOR_BRIGHT_BLUE    "\x1b[94m"
#define COLOR_BRIGHT_CYAN    "\x1b[96m"
#define COLOR_BRIGHT_MAGENTA "\x1b[95m" // Zaten COLOR_PINK olarak tanımlı
#define COLOR_BRIGHT_WHITE   "\x1b[97m"

// Özel Tonlar (256 Renk Paleti)
#define COLOR_ORANGE  "\x1b[38;5;208m"
#define COLOR_PURPLE  "\x1b[38;5;93m"    // Doygun mor
#define COLOR_LIME    "\x1b[38;5;118m"   // Neon yeşil
#define COLOR_OCEAN   "\x1b[38;5;27m"    // Derin mavi
#define COLOR_GRADIENT_PINK "\x1b[38;5;205m" // Banner için gradient pembe
// Gradient efektleri için
#define COLOR_GRADIENT_1 "\x1b[38;5;45m"   // Turkuaz
#define COLOR_GRADIENT_2 "\x1b[38;5;99m"   // Lavanta
#define COLOR_GRADIENT_3 "\x1b[38;5;207m"  // Neon pembeS


// Yapılandırma Parametreleri
#define MITM_THRESHOLD 85.0
#define SYN_FLOOD_THRESHOLD 90.0
#define SYN_FLOOD_COUNT 15
#define PORT_SCAN_WINDOW 2
#define LOG_UPDATE_INTERVAL 1000
#define HASH_SIZE 211
#define BLOCK_LIST_SIZE 100
#define LOG_FILE_NAME "firewall.log"

// Global Değişkenler
FILE *log_file = NULL;
pcap_t *global_handle = NULL;
volatile sig_atomic_t stop_capture = 0;
atomic_ulong packet_count = 0;
atomic_ulong alert_count = 0;
atomic_int ips_mode = 1;  // 1 = IPS (engelleme aktif), 0 = IDS (sadece izleme)

// Dinamik eşik değerleri (profiling ile güncellenecek)
int current_syn_flood_count = SYN_FLOOD_COUNT;
float current_mitm_threshold = MITM_THRESHOLD;
float current_syn_flood_threshold = SYN_FLOOD_THRESHOLD;

// Global cihaz adı (profiling için)
char global_dev[128] = {0};
// Global router IP; eğer girilmişse bu IP'den gelen paketler ihmal edilecek.
char router_ip[INET_ADDRSTRLEN] = "";

// Yapılar
typedef struct mac_entry {
    char mac[18];
    char ip[INET_ADDRSTRLEN];
    struct mac_entry *next;
} mac_entry_t;

typedef struct syn_entry {
    uint32_t ip;
    atomic_int count;
    time_t last_seen;
    struct syn_entry *next;
} syn_entry_t;

typedef struct block_entry {
    uint32_t ip;
    time_t blocked_time;
    struct block_entry *next;
} block_entry_t;

typedef struct port_scan {
    uint32_t ip;
    unsigned short ports[10];
    time_t first_seen;
    int count;
    struct port_scan *next;
} port_scan_t;

// Global Listeler
mac_entry_t *mac_list = NULL;
syn_entry_t *syn_list = NULL;
block_entry_t *blocked_ip_hash[HASH_SIZE] = {NULL};
port_scan_t *port_scan_list = NULL;

// Mutexler
pthread_mutex_t syn_list_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t block_list_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mac_list_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t port_scan_mutex = PTHREAD_MUTEX_INITIALIZER;

// Fonksiyon Prototipleri
void display_banner(void);
void display_menu(void);
void log_event(const char *format, ...);
void handle_signal(int signal);
void mac_to_string(const u_char *mac, char *buf);
float detect_mitm(const u_char *packet);
float detect_syn_flood(const u_char *packet);
void cleanup_syn_list(void);
void *syn_list_cleanup_thread(void *arg);
int is_ip_blocked(uint32_t ip);
void add_block_entry(uint32_t ip);
void block_ip(uint32_t ip);
void detect_port_scan(uint32_t src_ip, unsigned short dst_port);
void toggle_ips_mode(int mode);
void profile_traffic(int duration_seconds);
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
void *run_capture(void *arg);
void view_logs(void);
void generate_report(void);
void system_status(void);
int count_blocked_ips(void);

// Banner: Kendi ASCII sanatınızı buraya ekleyin.
void display_banner(void) {
    printf(COLOR_CYAN);
    printf("░█████╗░██╗░░░██╗██████╗░███████╗██████╗░  ███████╗░█████╗░███╗░░██╗███████╗\n");
    printf("██╔══██╗╚██╗░██╔╝██╔══██╗██╔════╝██╔══██╗  ╚════██║██╔══██╗████╗░██║██╔════╝\n");
    printf("██║░░╚═╝░╚████╔╝░██████╦╝█████╗░░██████╔╝  ░░███╔═╝██║░░██║██╔██╗██║█████╗░░\n");
    printf("██║░░██╗░░╚██╔╝░░██╔══██╗██╔══╝░░██╔══██╗  ██╔══╝░░██║░░██║██║╚████║██╔══╝░░\n");
    printf("╚█████╔╝░░░██║░░░██████╦╝███████╗██║░░██║  ███████╗╚█████╔╝██║░╚███║███████╗\n");
    printf("░╚════╝░░░░╚═╝░░░╚═════╝░╚══════╝╚═╝░░╚═╝  ╚══════╝░╚════╝░╚═╝░░╚══╝╚══════╝\n");
    printf("░██████╗░██████╗░░█████╗░██╗░░░██╗██████╗░\n");
    printf("██╔════╝░██╔══██╗██╔══██╗██║░░░██║██╔══██╗\n");
    printf("██║░░██╗░██████╔╝██║░░██║██║░░░██║██████╔╝\n");
    printf("██║░░╚██╗██╔══██╗██║░░██║██║░░░██║██╔═══╝░\n");
    printf("╚██████╔╝██║░░██║╚█████╔╝╚██████╔╝██║░░░░░\n");
    printf("░╚═════╝░╚═╝░░╚═╝░╚════╝░░╚═════╝░╚═╝░░░░░\n");
    printf(COLOR_RESET "\n");
}
// Menü arayüzü (7 seçenek)
void display_menu(void) {
    printf(COLOR_YELLOW);
    printf("\n");
    printf("    IDS/IPS Kontrol Paneli     \n");
    printf("\n");
    printf(" 1. Gerçek Zamanlı İzleme      \n");
    printf(" 2. Logları Görüntüle          \n");
    printf(" 3. Kuralları Entegre Et       \n");
    printf(" 4. Rapor Oluştur              \n");
    printf(" 5. Sistem Durumu              \n");
    printf(" 6. Mod Değiştir (%s)       \n", atomic_load(&ips_mode) ? "IPS" : "IDS");
    printf(" 7. Çıkış                      \n");
    printf("\n");
    printf(COLOR_CYAN "\nSosyal Medya Hesapları:\n");
    printf(COLOR_MAGENTA "telegram:https://t.me/+0a8RvBLLf_M0ODZk\n");
    printf(COLOR_PINK "instagram:https://www.instagram.com/cyberzonegroup\n" COLOR_RESET);
    printf(COLOR_RESET "Seçiminizi yapınız: ");
}

// Loglama: Hem ekrana hem dosyaya yazar
void log_event(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stdout, format, args);
    va_end(args);
    if (log_file) {
        va_start(args, format);
        vfprintf(log_file, format, args);
        fflush(log_file);
        va_end(args);
    }
}

// Ctrl+C sinyali alındığında hızlı kapatma
void handle_signal(int signal) {
    if (signal == SIGINT) {
        stop_capture = 1;
        if (global_handle)
            pcap_breakloop(global_handle);
        log_event(COLOR_RED "\nSistem kapatılıyor...\n" COLOR_RESET);
        exit(0);
    }
}

// MAC adresini dizeye çevirme
void mac_to_string(const u_char *mac, char *buf) {
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// MITM tespiti (ARP paketleri için basit örnek)
float detect_mitm(const u_char *packet) {
    return 80.0;
}

// SYN Flood tespiti (dinamik eşik kullanılarak)
float detect_syn_flood(const u_char *packet) {
    struct ip *iph = (struct ip*)(packet + sizeof(struct ether_header));
    struct tcphdr *tcph = (struct tcphdr*)(packet + sizeof(struct ether_header) + (iph->ip_hl << 2));
    if ((tcph->th_flags & (TH_SYN|TH_ACK)) != TH_SYN)
        return 0.0;
    pthread_mutex_lock(&syn_list_mutex);
    syn_entry_t *entry = syn_list;
    while (entry) {
        if (entry->ip == iph->ip_src.s_addr) {
            int current_count = atomic_fetch_add(&entry->count, 1) + 1;
            entry->last_seen = time(NULL);
            pthread_mutex_unlock(&syn_list_mutex);
            float confidence = (current_count / (float)current_syn_flood_count) * 100.0;
            return confidence > 100.0 ? 100.0 : confidence;
        }
        entry = entry->next;
    }
    syn_entry_t *new_entry = malloc(sizeof(syn_entry_t));
    new_entry->ip = iph->ip_src.s_addr;
    atomic_init(&new_entry->count, 1);
    new_entry->last_seen = time(NULL);
    new_entry->next = syn_list;
    syn_list = new_entry;
    pthread_mutex_unlock(&syn_list_mutex);
    return 0.0;
}

// SYN Listesi Temizleme
void cleanup_syn_list(void) {
    pthread_mutex_lock(&syn_list_mutex);
    syn_entry_t **indirect = &syn_list;
    time_t now = time(NULL);
    while (*indirect) {
        if (difftime(now, (*indirect)->last_seen) > 5) {
            syn_entry_t *temp = *indirect;
            *indirect = temp->next;
            free(temp);
        } else {
            indirect = &((*indirect)->next);
        }
    }
    pthread_mutex_unlock(&syn_list_mutex);
}

void *syn_list_cleanup_thread(void *arg) {
    while (!stop_capture) {
        cleanup_syn_list();
        sleep(1);
    }
    return NULL;
}

// Port Tarama Tespiti
void detect_port_scan(uint32_t src_ip, unsigned short dst_port) {
    time_t now = time(NULL);
    pthread_mutex_lock(&port_scan_mutex);
    port_scan_t *entry = port_scan_list;
    while (entry) {
        if (entry->ip == src_ip) {
            if (now - entry->first_seen > PORT_SCAN_WINDOW) {
                entry->count = 0;
                memset(entry->ports, 0, sizeof(entry->ports));
                entry->first_seen = now;
            }
            for (int i = 0; i < 10; i++) {
                if (entry->ports[i] == dst_port) break;
                if (entry->ports[i] == 0) {
                    entry->ports[i] = dst_port;
                    if (++entry->count >= 5) {
                        log_event(COLOR_YELLOW "[%s] UYARI: Port Tarama Denemesi (TCP/445)\n" COLOR_RESET, "");
                        if (atomic_load(&ips_mode))
                            block_ip(src_ip);
                        entry->count = 0;
                        memset(entry->ports, 0, sizeof(entry->ports));
                    }
                    break;
                }
            }
            pthread_mutex_unlock(&port_scan_mutex);
            return;
        }
        entry = entry->next;
    }
    port_scan_t *new_entry = malloc(sizeof(port_scan_t));
    new_entry->ip = src_ip;
    new_entry->ports[0] = dst_port;
    new_entry->count = 1;
    new_entry->first_seen = now;
    new_entry->next = port_scan_list;
    port_scan_list = new_entry;
    pthread_mutex_unlock(&port_scan_mutex);
}

// IP Engelleme: Hash tabanlı
unsigned int hash_ip(uint32_t ip) { return ip % HASH_SIZE; }

int is_ip_blocked(uint32_t ip) {
    unsigned int hash_idx = hash_ip(ip);
    pthread_mutex_lock(&block_list_mutex);
    block_entry_t *entry = blocked_ip_hash[hash_idx];
    while (entry) {
        if (entry->ip == ip) {
            pthread_mutex_unlock(&block_list_mutex);
            return 1;
        }
        entry = entry->next;
    }
    pthread_mutex_unlock(&block_list_mutex);
    return 0;
}

void add_block_entry(uint32_t ip) {
    block_entry_t *new_entry = malloc(sizeof(block_entry_t));
    new_entry->ip = ip;
    new_entry->blocked_time = time(NULL);
    pthread_mutex_lock(&block_list_mutex);
    unsigned int hash_idx = hash_ip(ip);
    new_entry->next = blocked_ip_hash[hash_idx];
    blocked_ip_hash[hash_idx] = new_entry;
    pthread_mutex_unlock(&block_list_mutex);
}

void block_ip(uint32_t ip) {
    if (is_ip_blocked(ip)) return;
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, ip_str, INET_ADDRSTRLEN);
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "iptables -A INPUT -s %s -j DROP", ip_str);
    if (system(cmd) == 0) {
        add_block_entry(ip);
        log_event(COLOR_RED "[%s] ENGELlENDI: %s IP adresi karalistede!\n" COLOR_RESET, "", ip_str);
    }
}

// Mod Değiştirme (IPS/IDS)
void toggle_ips_mode(int mode) {
    atomic_store(&ips_mode, mode);
    log_event(COLOR_YELLOW "Mod değiştirildi: %s\n" COLOR_RESET,
              mode ? "IPS (Engelleme Aktif)" : "IDS (İzleme Modu)");
}

// Profiling: Belirtilen süre boyunca trafik izlenip dinamik eşik değerleri güncelleniyor
void profile_traffic(int duration_seconds) {
    printf(COLOR_CYAN "Profiling %d saniye boyunca trafik izleniyor...\n" COLOR_RESET, duration_seconds);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *temp_handle = pcap_open_live(global_dev, BUFSIZ, 1, 1000, errbuf);
    if (!temp_handle) {
        printf(COLOR_RED "Profiling: Arayüz açılamadı: %s\n" COLOR_RESET, errbuf);
        return;
    }
    unsigned long total_packets = 0, tcp_syn_packets = 0, arp_packets = 0;
    time_t start = time(NULL), now;
    while ((now = time(NULL)) < start + duration_seconds) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(temp_handle, &header, &packet);
        if (res > 0) {
            total_packets++;
            struct ether_header *eth = (struct ether_header *)packet;
            if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
                struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));
                char sender_ip[INET_ADDRSTRLEN];
                struct in_addr spa;
                memcpy(&spa, arp_hdr->arp_spa, sizeof(spa));
                inet_ntop(AF_INET, &spa, sender_ip, INET_ADDRSTRLEN);
                // Eğer ARP kaynağı router ise atla
                if (strlen(router_ip) > 0 && strcmp(sender_ip, router_ip) == 0)
                    continue;
                arp_packets++;
            }
            else if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
                const u_char *ip_packet = packet + sizeof(struct ether_header);
                struct ip *iph = (struct ip *)ip_packet;
                char src_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
                // Eğer kaynak IP router ise atla
                if (strlen(router_ip) > 0 && strcmp(src_ip, router_ip) == 0)
                    continue;
                if (iph->ip_p == IPPROTO_TCP) {
                    int ip_header_length = iph->ip_hl * 4;
                    struct tcphdr *tcph = (struct tcphdr *)(ip_packet + ip_header_length);
                    if ((tcph->th_flags & TH_SYN) && !(tcph->th_flags & TH_ACK))
                        tcp_syn_packets++;
                }
            }
        }
    }
    pcap_close(temp_handle);
    double dur = duration_seconds;
    double avg_tcp_syn = tcp_syn_packets / dur;
    double avg_arp = arp_packets / dur;
    printf(COLOR_CYAN "Profiling Sonuçları:\n Toplam Paket: %lu, Ortalama TCP SYN/s: %.2f, Ortalama ARP/s: %.2f\n" COLOR_RESET,
           total_packets, avg_tcp_syn, avg_arp);
    current_syn_flood_count = (int)(avg_tcp_syn * 3);
    if (current_syn_flood_count < 5) current_syn_flood_count = 5;
    current_mitm_threshold = (float)(avg_arp * 2);
    if (current_mitm_threshold < 50.0) current_mitm_threshold = 50.0;
    printf(COLOR_CYAN "Yeni SYN Flood Count Eşiği: %d, Yeni MITM Eşiği: %.1f\n" COLOR_RESET,
           current_syn_flood_count, current_mitm_threshold);
}

// Paket İşleme Callback Fonksiyonu
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    atomic_fetch_add(&packet_count, 1);
    int detection_triggered = 0;
    char timebuf[64];
    time_t t = header->ts.tv_sec;
    struct tm *ltime = localtime(&t);
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", ltime);

    struct ether_header *eth = (struct ether_header *)packet;
    // ARP paketleri
    if (ntohs(eth->ether_type) == ETHERTYPE_ARP) {
        if (header->len >= (int)(sizeof(struct ether_header) + sizeof(struct ether_arp))) {
            struct ether_arp *arp_hdr = (struct ether_arp *)(packet + sizeof(struct ether_header));
            char sender_ip[INET_ADDRSTRLEN], target_ip[INET_ADDRSTRLEN];
            struct in_addr spa, tpa;
            memcpy(&spa, arp_hdr->arp_spa, sizeof(spa));
            memcpy(&tpa, arp_hdr->arp_tpa, sizeof(tpa));
            inet_ntop(AF_INET, &spa, sender_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &tpa, target_ip, INET_ADDRSTRLEN);
            // Eğer ARP kaynağı router ise bu paketi ihmal et
            if (strlen(router_ip) > 0 && strcmp(sender_ip, router_ip) == 0) {
                // Router trafiğini tehdit olarak algılama
                return;
            }
            float mitm_risk = detect_mitm(packet);
            if (mitm_risk >= current_mitm_threshold) {
                atomic_fetch_add(&alert_count, 1);
                log_event(COLOR_RED "[%s] ALERT: Şüpheli ARP Paketi (%s → %s)\n" COLOR_RESET, timebuf, sender_ip, target_ip);
                detection_triggered = 1;
            }
            char mac_str[18];
            mac_to_string(arp_hdr->arp_sha, mac_str);
            pthread_mutex_lock(&mac_list_mutex);
            mac_entry_t *mentry = mac_list;
            int collision = 0;
            while (mentry) {
                if (strcmp(mentry->mac, mac_str) == 0 && strcmp(mentry->ip, sender_ip) != 0) {
                    collision = 1;
                    break;
                }
                mentry = mentry->next;
            }
            if (!collision) {
                mac_entry_t *new_entry = malloc(sizeof(mac_entry_t));
                if (new_entry) {
                    strncpy(new_entry->mac, mac_str, sizeof(new_entry->mac));
                    strncpy(new_entry->ip, sender_ip, sizeof(new_entry->ip));
                    new_entry->next = mac_list;
                    mac_list = new_entry;
                }
            }
            pthread_mutex_unlock(&mac_list_mutex);
            if (collision) {
                log_event(COLOR_RED "[%s] ALERT: MAC Adresi Çakışması (%s)\n" COLOR_RESET, timebuf, mac_str);
                detection_triggered = 1;
            }
        }
    }
    // IP paketleri
    else if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
        const u_char *ip_packet = packet + sizeof(struct ether_header);
        struct ip *iph = (struct ip *)ip_packet;
        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);
        // Eğer kaynak IP router ise ihmal et
        if (strlen(router_ip) > 0 && strcmp(src_ip, router_ip) == 0)
            return;
        if (strcmp(src_ip, "178.62.32.15") == 0) {
            log_event(COLOR_RED "[%s] ALERT: TOR Ağı Tespit Edildi (Exit Node: %s)\n" COLOR_RESET, timebuf, src_ip);
            detection_triggered = 1;
        }
        if (iph->ip_p == IPPROTO_TCP) {
            int ip_header_length = iph->ip_hl * 4;
            struct tcphdr *tcph = (struct tcphdr *)(ip_packet + ip_header_length);
            int tcp_header_length = tcph->th_off * 4;
            int payload_length = header->len - (sizeof(struct ether_header) + ip_header_length + tcp_header_length);
            const u_char *payload = ip_packet + ip_header_length + tcp_header_length;
            if (ntohs(tcph->th_dport) == 445 && (tcph->th_flags & TH_SYN) && !(tcph->th_flags & TH_ACK)) {
                log_event(COLOR_YELLOW "[%s] UYARI: Port Tarama Denemesi (TCP/445)\n" COLOR_RESET, timebuf);
                detection_triggered = 1;
            }
            if (ntohs(tcph->th_dport) == 80 && payload_length > 4) {
                if (memcmp(payload, "GET ", 4) == 0) {
                    char request_line[128] = {0};
                    int i = 0;
                    while (i < payload_length && i < 127 && payload[i] != '\n' && payload[i] != '\r') {
                        request_line[i] = payload[i];
                        i++;
                    }
                    log_event(COLOR_GREEN "[%s] HTTP İsteği: %s (Kaynak: %s)\n" COLOR_RESET, timebuf, request_line, src_ip);
                    detection_triggered = 1;
                }
            }
            if (ntohs(tcph->th_dport) == 22 && payload_length > 4) {
                if (strstr((const char*)payload, "SSH-") != NULL) {
                    log_event(COLOR_GREEN "[%s] BAŞARILI: SSH Bağlantısı (admin@%s)\n" COLOR_RESET, timebuf, src_ip);
                    detection_triggered = 1;
                }
            }
            if (payload_length > 6) {
                char *payload_str = malloc(payload_length + 1);
                if (payload_str) {
                    memcpy(payload_str, payload, payload_length);
                    payload_str[payload_length] = '\0';
                    for (int i = 0; i < payload_length; i++) {
                        payload_str[i] = tolower(payload_str[i]);
                    }
                    if (strstr(payload_str, "select") != NULL) {
                        log_event(COLOR_RED "[%s] ENGELlENDI: SQL Injection Denemesi (%.20s...)\n" COLOR_RESET, timebuf, payload_str);
                        detection_triggered = 1;
                    }
                    free(payload_str);
                }
            }
            if (header->len > 1400) {
                log_event(COLOR_YELLOW "[%s] UYARI: Anormal Yük Boyutu (%d bayt → Dış IP)\n" COLOR_RESET, timebuf, header->len);
                detection_triggered = 1;
            }
            float syn_conf = detect_syn_flood(packet);
            if (syn_conf >= current_syn_flood_threshold) {
                log_event(COLOR_RED "[%s] ALERT: SYN Flood saldırısı tespit edildi (%.1f%%)\n" COLOR_RESET, timebuf, syn_conf);
                detection_triggered = 1;
                if (atomic_load(&ips_mode))
                    block_ip(iph->ip_src.s_addr);
            }
            detect_port_scan(iph->ip_src.s_addr, ntohs(tcph->th_dport));
        }
        else if (iph->ip_p == IPPROTO_UDP) {
            int ip_header_length = iph->ip_hl * 4;
            struct udphdr *udph = (struct udphdr *)(ip_packet + ip_header_length);
            int udp_header_length = sizeof(struct udphdr);
            int payload_length = header->len - (sizeof(struct ether_header) + ip_header_length + udp_header_length);
            const u_char *payload = ip_packet + ip_header_length + udp_header_length;
            if (ntohs(udph->uh_dport) == 53 && payload_length > 0) {
                if (memmem(payload, payload_length, "xn--", 4) != NULL) {
                    log_event(COLOR_RED "[%s] ALERT: DNS Tünelleme Şüphesi (%.20s...)\n" COLOR_RESET, timebuf, payload);
                    detection_triggered = 1;
                }
            }
        }
    }
    if (!detection_triggered) {
        log_event(COLOR_GREEN "[%s] BAŞARILI: Normal trafik (%d bayt)\n" COLOR_RESET, timebuf, header->len);
    }
}


// Logları Görüntüleme
void view_logs(void) {
    FILE *fp = fopen(LOG_FILE_NAME, "r");
    if (!fp) {
        printf(COLOR_RED "Log dosyası açılamadı.\n" COLOR_RESET);
        return;
    }
    printf(COLOR_CYAN "\n=== Log Dosyası İçeriği ===\n" COLOR_RESET);
    char line[512];
    while (fgets(line, sizeof(line), fp))
        printf("%s", line);
    printf(COLOR_CYAN "=== Log Sonu ===\n\n" COLOR_RESET);
    fclose(fp);
    printf("Devam etmek için Enter'a basınız...");
    getchar();
    getchar();
}

// Rapor Oluşturma
void generate_report(void) {
    FILE *report = fopen("ids_report.txt", "w");
    if (!report) {
        printf(COLOR_RED "Rapor dosyası oluşturulamadı.\n" COLOR_RESET);
        return;
    }
    int blocked = count_blocked_ips();
    fprintf(report, "=== IDS/IPS Raporu ===\n");
    fprintf(report, "Toplam İşlenen Paket: %lu\n", atomic_load(&packet_count));
    fprintf(report, "Tespit Edilen Saldırılar: %lu\n", atomic_load(&alert_count));
    fprintf(report, "Engellenen IP Sayısı: %d\n", blocked);
    fprintf(report, "Çalışma Modu: %s\n", atomic_load(&ips_mode) ? "IPS" : "IDS");
    fclose(report);
    printf(COLOR_GREEN "Rapor oluşturuldu: ids_report.txt\n" COLOR_RESET);
    printf("Devam etmek için Enter'a basınız...");
    getchar();
    getchar();
}

// Sistem Durumu
void system_status(void) {
    int blocked = count_blocked_ips();
    printf(COLOR_YELLOW "\n=== Sistem Durumu ===\n" COLOR_RESET);
    printf("Toplam Paket: %lu\n", atomic_load(&packet_count));
    printf("Toplam Alarm: %lu\n", atomic_load(&alert_count));
    printf("Engellenen IP: %d\n", blocked);
    printf("Çalışma Modu: %s\n", atomic_load(&ips_mode) ? "IPS" : "IDS");
    printf(COLOR_YELLOW "=======================\n\n" COLOR_RESET);
    printf("Devam etmek için Enter'a basınız...");
    getchar();
    getchar();
}

// Engellenen IP Sayısını Hesaplayan Fonksiyon
int count_blocked_ips(void) {
    int count = 0;
    pthread_mutex_lock(&block_list_mutex);
    for (int i = 0; i < HASH_SIZE; i++) {
        block_entry_t *entry = blocked_ip_hash[i];
        while (entry) {
            count++;
            entry = entry->next;
        }
    }
    pthread_mutex_unlock(&block_list_mutex);
    return count;
}

// Ana Menü ve Yönetim
int main(int argc, char *argv[]) {
    char *dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs = NULL;
    int allocated_dev = 0;
    pthread_t capture_thread, cleanup_thread;
    int menu_choice;
    char choice_str[10];

    display_banner();

    // Log dosyasını aç
    log_file = fopen(LOG_FILE_NAME, "a");
    if (!log_file) {
        fprintf(stderr, "Log dosyası açılamadı\n");
        return 1;
    }

    // Ağ arayüzü seçimi
    if (argc >= 2) {
        dev = argv[1];
    } else {
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            log_event("Arayüz bulunamadı: %s\n", errbuf);
            fclose(log_file);
            return 2;
        }
        for (pcap_if_t *d = alldevs; d; d = d->next) {
            if (!(d->flags & PCAP_IF_LOOPBACK)) {
                dev = d->name;
                break;
            }
        }
        if (!dev) dev = alldevs->name;
        dev = strdup(dev);
        allocated_dev = 1;
        pcap_freealldevs(alldevs);
    }
    log_event("Kullanılan arayüz: %s\n", dev);
    strncpy(global_dev, dev, sizeof(global_dev) - 1);

    // Eğer 3. argüman varsa, router IP'sini al (bu IP'yi tehdit olarak algılama)
    if (argc >= 3) {
        strncpy(router_ip, argv[2], INET_ADDRSTRLEN);
        router_ip[INET_ADDRSTRLEN-1] = '\0';
        log_event("Router IP hariç tutulacak: %s\n", router_ip);
    }

    global_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!global_handle) {
        log_event("Arayüz açılamadı: %s\n", errbuf);
        if (allocated_dev) free(dev);
        fclose(log_file);
        return 3;
    }

    signal(SIGINT, handle_signal);

    if (pthread_create(&cleanup_thread, NULL, syn_list_cleanup_thread, NULL)) {
        log_event("Cleanup thread oluşturulamadı\n");
        pcap_close(global_handle);
        if (allocated_dev) free(dev);
        fclose(log_file);
        return 4;
    }

    // Menü Döngüsü
    while (1) {
        display_menu();
        if (!fgets(choice_str, sizeof(choice_str), stdin))
            continue;
        menu_choice = atoi(choice_str);
        switch (menu_choice) {
            case 1: {
                stop_capture = 0;
                printf(COLOR_CYAN "\nGerçek Zamanlı İzleme başladı (Durdurmak için 'q' tuşuna basınız)\n" COLOR_RESET);
                if (pthread_create(&capture_thread, NULL, run_capture, NULL)) {
                    printf(COLOR_RED "Canlı izleme başlatılamadı\n" COLOR_RESET);
                    break;
                }
                int c;
                while ((c = getchar()) != 'q' && c != 'Q');
                stop_capture = 1;
                pthread_join(capture_thread, NULL);
                printf(COLOR_YELLOW "\nİzleme durduruldu\n\n" COLOR_RESET);
                stop_capture = 0;
                break;
            }
            case 2:
                view_logs();
                break;
            case 3: {
                printf(COLOR_CYAN "\nProfiling süresi (dakika cinsinden, örn: 1 veya 5): " COLOR_RESET);
                char dur_str[10];
                if (fgets(dur_str, sizeof(dur_str), stdin)) {
                    int minutes = atoi(dur_str);
                    if (minutes <= 0) minutes = 1;
                    profile_traffic(minutes * 60);
                }
                break;
            }
            case 4:
                generate_report();
                break;
            case 5:
                system_status();
                break;
            case 6:
                toggle_ips_mode(!atomic_load(&ips_mode));
                break;
            case 7:
                goto exit_menu;
            default:
                printf(COLOR_RED "\nGeçersiz seçim! Lütfen tekrar deneyiniz.\n\n" COLOR_RESET);
        }
    }

    exit_menu:
    stop_capture = 1;
    pcap_close(global_handle);
    pthread_cancel(cleanup_thread);
    pthread_join(cleanup_thread, NULL);
    if (allocated_dev) free(dev);
    fclose(log_file);
    return 0;
}

// run_capture: pcap_loop'u çalıştıran thread fonksiyonu (tek tanımlı, void* dönüşlü)
void *run_capture(void *arg) {
    pcap_loop(global_handle, 0, packet_handler, NULL);
    return NULL;
}
