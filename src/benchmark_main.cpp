#include <Arduino.h>
#include <SPI.h>
#include <mbedtls/gcm.h>
#include <mbedtls/version.h>
#include <string.h>
#include <mbedtls/chachapoly.h>

extern "C" {
#include <wizchip_conf.h>
#include <socket.h>
#include <w5500.h>
}

extern "C" {
    extern volatile uint64_t bench_state_us;
    extern volatile uint64_t bench_free_us;
    extern volatile uint64_t bench_spi_us;
    extern volatile uint64_t bench_send_us;
    extern volatile uint32_t bench_calls;
    extern volatile uint32_t bench_busy;
}

// Choose one benchmark. Encryption mode does not initialize Ethernet.
#define BENCH_AES_GCM 1
#define BENCH_RAW_TCP 2
#define BENCH_MODE BENCH_RAW_TCP

// AES-128-GCM encryption-only benchmark (not a full TLS benchmark).
constexpr size_t AES_BLOCK_SIZE = 16384;
constexpr uint32_t AES_TOTAL_BYTES = 100UL * 1024UL * 1024UL;
static uint8_t aesPlaintext[AES_BLOCK_SIZE];
static uint8_t aesCiphertext[AES_BLOCK_SIZE];

// Test-only key. Never use it for production encryption.
static const uint8_t aesKey[16] = {
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
    0x98, 0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F
};


void runChaChaBenchmark() {
    Serial.println();
    Serial.println("===== CHACHA20-POLY1305 BENCHMARK =====");

    static uint8_t plaintext[16384];
    static uint8_t ciphertext[16384];

    uint8_t key[32] = {0};
    uint8_t nonce[12] = {0};
    uint8_t tag[16] = {0};

    for (size_t i = 0; i < sizeof(plaintext); i++) {
        plaintext[i] = (uint8_t)((i * 37 + 19) & 0xFF);
    }

    mbedtls_chachapoly_context ctx;
    mbedtls_chachapoly_init(&ctx);

    int ret = mbedtls_chachapoly_setkey(&ctx, key);

    if (ret != 0) {
        Serial.print("Setkey failed: ");
        Serial.println(ret);
        mbedtls_chachapoly_free(&ctx);
        return;
    }

    constexpr uint32_t TOTAL = 100UL * 1024UL * 1024UL;
    constexpr size_t BLOCK = 16384;

    uint32_t encrypted = 0;
    uint32_t records = 0;

    uint32_t startMs = millis();

    while (encrypted < TOTAL) {
        uint64_t counter = records;

        for (int i = 0; i < 8; i++) {
            nonce[11 - i] = (uint8_t)(counter & 0xFF);
            counter >>= 8;
        }

        ret = mbedtls_chachapoly_encrypt_and_tag(
            &ctx,
            BLOCK,
            nonce,
            nullptr,
            0,
            plaintext,
            ciphertext,
            tag
        );

        if (ret != 0) {
            Serial.print("Encryption failed: ");
            Serial.println(ret);
            break;
        }

        encrypted += BLOCK;
        records++;
    }

    uint32_t elapsedMs = millis() - startMs;

    double mbps = elapsedMs > 0
        ? ((double)encrypted * 8.0) /
          ((double)elapsedMs * 1000.0)
        : 0.0;

    Serial.println();
    Serial.println("========== RESULTS ==========");

    Serial.print("Status: ");
    Serial.println(ret == 0 && encrypted == TOTAL
                       ? "COMPLETED" : "FAILED");

    Serial.print("Bytes encrypted: ");
    Serial.println(encrypted);

    Serial.print("Elapsed time (ms): ");
    Serial.println(elapsedMs);

    Serial.print("Throughput (Mbit/s): ");
    Serial.println(mbps, 3);

    Serial.println("=============================");

    mbedtls_chachapoly_free(&ctx);
}


void runEncryptionBenchmark() {
    Serial.println("========== AES-128-GCM BENCHMARK ==========");
    Serial.print("mbedTLS: ");
    Serial.println(MBEDTLS_VERSION_STRING);

    for (size_t i = 0; i < AES_BLOCK_SIZE; ++i) {
        aesPlaintext[i] = (uint8_t)((i * 37 + 19) & 0xFF);
    }

    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, aesKey, 128);
    if (ret != 0) {
        Serial.print("[ERROR] setkey: ");
        Serial.println(ret);
        mbedtls_gcm_free(&ctx);
        return;
    }

    uint8_t nonce[12] = {0};
    uint8_t tag[16] = {0};
    uint32_t encrypted = 0;
    uint32_t record = 0;
    uint32_t lastReport = millis();
    uint32_t start = millis();
    bool failed = false;

    while (encrypted < AES_TOTAL_BYTES) {
        size_t count = AES_TOTAL_BYTES - encrypted;
        if (count > AES_BLOCK_SIZE) count = AES_BLOCK_SIZE;

        // Unique 96-bit nonce per record for this fixed test key.
        uint64_t sequence = record;
        memset(nonce, 0, sizeof(nonce));
        for (int i = 11; i >= 4; --i) {
            nonce[i] = (uint8_t)(sequence & 0xFF);
            sequence >>= 8;
        }

        ret = mbedtls_gcm_crypt_and_tag(
            &ctx, MBEDTLS_GCM_ENCRYPT, count,
            nonce, sizeof(nonce),
            nullptr, 0,
            aesPlaintext, aesCiphertext,
            sizeof(tag), tag
        );
        if (ret != 0) {
            Serial.print("[ERROR] GCM encrypt: ");
            Serial.println(ret);
            failed = true;
            break;
        }
        encrypted += (uint32_t)count;
        ++record;

        uint32_t now = millis();
        if (now - lastReport >= 1000) {
            double seconds = (now - start) / 1000.0;
            double mbps = seconds > 0 ? (encrypted * 8.0) / (seconds * 1000000.0) : 0;
            Serial.print("[AES] ");
            Serial.print(encrypted / 1048576.0, 2);
            Serial.print(" MiB | ");
            Serial.print(mbps, 2);
            Serial.println(" Mbit/s");
            lastReport = now;
        }
    }

    uint32_t elapsed = millis() - start;
    mbedtls_gcm_free(&ctx);
    Serial.println("========== AES RESULTS ==========");
    Serial.print("Status: ");
    Serial.println(!failed && encrypted == AES_TOTAL_BYTES ? "COMPLETED" : "FAILED");
    Serial.print("Bytes encrypted: ");
    Serial.println(encrypted);
    Serial.print("Records: ");
    Serial.println(record);
    Serial.print("Elapsed (ms): ");
    Serial.println(elapsed);
    Serial.print("Throughput (Mbit/s): ");
    Serial.println(elapsed ? (encrypted * 8.0) / (elapsed * 1000.0) : 0, 3);
    Serial.println("=================================");
}

// ============================================================
// CRYOPHONE W5500 HARDWARE TCP BENCHMARK
//
// RP2350 + Arduino-Pico + SPI1
// WIZnet ioLibrary_Driver
//
// No lwIP, TLS, HTTP, SD card, or DHCP.
// ============================================================

// ---------------- HARDWARE ----------------

constexpr uint8_t PIN_MISO = 8;
constexpr uint8_t PIN_CS   = 9;
constexpr uint8_t PIN_SCK  = 10;
constexpr uint8_t PIN_MOSI = 11;
constexpr uint8_t PIN_RST  = 24;

// ---------------- SPI ----------------

constexpr uint32_t SPI_SPEED_HZ = 40000000;

SPISettings wizSPI(
    SPI_SPEED_HZ,
    MSBFIRST,
    SPI_MODE0
);

// ---------------- NETWORK ----------------

uint8_t localIP[4]  = {192, 168, 50, 2};
uint8_t gateway[4]  = {192, 168, 50, 1};
uint8_t subnet[4]   = {255, 255, 255, 0};
uint8_t serverIP[4] = {192, 168, 50, 1};

uint8_t mac[6] = {
    0x02, 0x43, 0x52, 0x59, 0x4F, 0x01
};

constexpr uint16_t SERVER_PORT = 5001;
constexpr uint16_t LOCAL_PORT  = 5002;

constexpr uint8_t SOCKET_NUMBER = 0;

// ---------------- BENCHMARK ----------------

constexpr size_t BUFFER_SIZE = 8192;

constexpr uint32_t TOTAL_BYTES =
    100UL * 1024UL * 1024UL;

constexpr uint32_t CONNECT_TIMEOUT_MS = 10000;
constexpr uint32_t TRANSFER_TIMEOUT_MS = 10000;

// 16 KiB TX and 16 KiB RX for socket 0.
// Other sockets are disabled.
uint8_t txSizes[8] = {16, 0, 0, 0, 0, 0, 0, 0};
uint8_t rxSizes[8] = {16, 0, 0, 0, 0, 0, 0, 0};

// ---------------- GLOBALS ----------------

uint8_t buffer[BUFFER_SIZE];

// ============================================================
// SPI CALLBACKS
// ============================================================

void wizSelect() {
    SPI1.beginTransaction(wizSPI);
    digitalWrite(PIN_CS, LOW);
}

void wizDeselect() {
    digitalWrite(PIN_CS, HIGH);
    SPI1.endTransaction();
}

uint8_t wizReadByte() {
    return SPI1.transfer(0x00);
}

void wizWriteByte(uint8_t data) {
    SPI1.transfer(data);
}

// Burst callbacks use SPI buffer transfers.
// This is important for throughput.

void wizReadBurst(uint8_t *buf, uint16_t len) {
    SPI1.transfer(nullptr, buf, len);
}

volatile uint64_t bench_burst_us = 0;
volatile uint32_t bench_burst_calls = 0;
volatile uint64_t bench_burst_bytes = 0;

volatile uint32_t burstSmall = 0;
volatile uint32_t burstMedium = 0;
volatile uint32_t burstLarge = 0;

void wizWriteBurst(uint8_t *buf, uint16_t len) {
    uint32_t start = micros();

    SPI1.transfer(buf, nullptr, len);

    bench_burst_us +=
        (uint32_t)(micros() - start);

    bench_burst_calls++;
    bench_burst_bytes += len;

    if (len <= 64) {
        burstSmall++;
    } else if (len <= 1024) {
        burstMedium++;
    } else {
        burstLarge++;
    }
}

// ============================================================
// HARDWARE INITIALIZATION
// ============================================================

void resetW5500() {
    Serial.println("[RESET] Resetting W5500...");

    pinMode(PIN_RST, OUTPUT);

    digitalWrite(PIN_RST, LOW);
    delay(100);

    digitalWrite(PIN_RST, HIGH);
    delay(100);

    Serial.println("[RESET] Complete.");
}

void prepareBuffer() {
    Serial.println("[BUFFER] Preparing data...");

    for (size_t i = 0; i < BUFFER_SIZE; i++) {
        buffer[i] =
            static_cast<uint8_t>((i * 37 + 19) & 0xFF);
    }

    Serial.println("[BUFFER] Ready.");
}

void printIP(const uint8_t *ip) {
    for (int i = 0; i < 4; i++) {
        Serial.print(ip[i]);

        if (i < 3) {
            Serial.print(".");
        }
    }
}

bool initializeW5500() {
    Serial.println();
    Serial.println("========== W5500 INIT ==========");

    Serial.println("[1] Configuring CS...");

    pinMode(PIN_CS, OUTPUT);
    digitalWrite(PIN_CS, HIGH);

    Serial.println("[2] Configuring SPI1...");

    SPI1.setRX(PIN_MISO);
    SPI1.setTX(PIN_MOSI);
    SPI1.setSCK(PIN_SCK);
    SPI1.begin();

    Serial.println("[3] Resetting hardware...");

    resetW5500();

    Serial.println("[4] Registering SPI callbacks...");

    reg_wizchip_cs_cbfunc(
        wizSelect,
        wizDeselect
    );

    reg_wizchip_spi_cbfunc(
        wizReadByte,
        wizWriteByte
    );

    reg_wizchip_spiburst_cbfunc(
        wizReadBurst,
        wizWriteBurst
    );

    Serial.println("[5] Checking chip version...");

    uint8_t version = getVERSIONR();

    Serial.print("W5500 version register: 0x");
    Serial.println(version, HEX);

    if (version != 0x04) {
        Serial.println(
            "[ERROR] W5500 version mismatch."
        );
        return false;
    }

    Serial.println("[6] Configuring socket memory...");

    if (wizchip_init(txSizes, rxSizes) != 0) {
        Serial.println(
            "[ERROR] W5500 memory initialization failed."
        );
        return false;
    }

    Serial.println("[7] Configuring network...");

    wiz_NetInfo netInfo = {};

    memcpy(netInfo.mac, mac, 6);
    memcpy(netInfo.ip, localIP, 4);
    memcpy(netInfo.sn, subnet, 4);
    memcpy(netInfo.gw, gateway, 4);

    netInfo.dhcp = NETINFO_STATIC;

    wizchip_setnetinfo(&netInfo);

    Serial.println("[8] Checking PHY link...");

    uint32_t start = millis();

    uint8_t linkStatus = PHY_LINK_OFF;

    while (millis() - start < 10000) {
        if (
            ctlwizchip(
                CW_GET_PHYLINK,
                &linkStatus
            ) == 0
        ) {
            if (linkStatus == PHY_LINK_ON) {
                break;
            }
        }

        delay(100);
    }

    if (linkStatus != PHY_LINK_ON) {
        Serial.println("[ERROR] Ethernet link down.");
        return false;
    }

    Serial.println("[9] Ethernet ready!");

    Serial.print("Local IP: ");
    printIP(localIP);
    Serial.println();

    Serial.print("Server IP: ");
    printIP(serverIP);
    Serial.println();

    Serial.print("SPI speed: ");
    Serial.print(SPI_SPEED_HZ / 1000000);
    Serial.println(" MHz");

    Serial.println("TCP engine: W5500 hardware");

    Serial.println("================================");

    return true;
}

// ============================================================
// TCP CONNECTION
// ============================================================

bool connectToServer() {
    Serial.println();
    Serial.println("[TCP] Opening hardware socket...");

    int8_t result = socket(
        SOCKET_NUMBER,
        Sn_MR_TCP,
        LOCAL_PORT,
        0
    );

    if (result != SOCKET_NUMBER) {
        Serial.print("[ERROR] socket(): ");
        Serial.println(result);
        return false;
    }

    Serial.println("[TCP] Connecting...");

    result = connect(
        SOCKET_NUMBER,
        serverIP,
        SERVER_PORT
    );

    if (result != SOCK_OK) {
        Serial.print("[ERROR] connect(): ");
        Serial.println(result);
        close(SOCKET_NUMBER);
        return false;
    }

    uint32_t start = millis();

    while (millis() - start < CONNECT_TIMEOUT_MS) {
        uint8_t status = getSn_SR(SOCKET_NUMBER);

        if (status == SOCK_ESTABLISHED) {
            Serial.println("[TCP] Connected!");
            return true;
        }

        if (status == SOCK_CLOSED) {
            Serial.println("[ERROR] Socket closed.");
            return false;
        }

        delay(1);
    }

    Serial.println("[ERROR] Connection timeout.");

    close(SOCKET_NUMBER);
    return false;
}

// ============================================================
// TCP BENCHMARK
// ============================================================

void runBenchmark() {
    Serial.println();
    Serial.println("========== TCP BENCHMARK ==========");

    if (!connectToServer()) {
        return;
    }

    Serial.println("[TCP] Starting 100 MiB transfer...");

    uint32_t bytesSent = 0;
    uint32_t sendCalls = 0;
    uint32_t busyCalls = 0;

    uint64_t totalSendUs = 0;

    uint32_t startMs = millis();
    uint32_t lastProgressMs = startMs;
    uint32_t lastSuccessMs = startMs;

    bool failed = false;

    while (bytesSent < TOTAL_BYTES) {
        uint32_t remaining = TOTAL_BYTES - bytesSent;

        uint16_t chunkSize =
            remaining < BUFFER_SIZE
                ? static_cast<uint16_t>(remaining)
                : static_cast<uint16_t>(BUFFER_SIZE);

        uint32_t sendStart = micros();

        int32_t result = send(
            SOCKET_NUMBER,
            buffer,
            chunkSize
        );

        uint32_t sendDuration =
            micros() - sendStart;

        totalSendUs += sendDuration;
        sendCalls++;

        if (result > 0) {
            bytesSent += static_cast<uint32_t>(result);
            lastSuccessMs = millis();
        }
        else if (result == SOCK_BUSY) {
            busyCalls++;
        }
        else {
            Serial.print("[ERROR] send(): ");
            Serial.println(result);

            Serial.print("[ERROR] Socket status: 0x");
            Serial.println(getSn_SR(SOCKET_NUMBER), HEX);

            Serial.print("[ERROR] Socket interrupts: 0x");
            Serial.println(getSn_IR(SOCKET_NUMBER), HEX);

            Serial.print("[ERROR] TX free space: ");
            Serial.println(getSn_TX_FSR(SOCKET_NUMBER));

            failed = true;
            break;
        }

        if (
            millis() - lastSuccessMs >
            TRANSFER_TIMEOUT_MS
        ) {
            Serial.println("[ERROR] Transfer stalled.");
            failed = true;
            break;
        }

        if (
            millis() - lastProgressMs >= 1000
        ) {
            float elapsed =
                (millis() - startMs) / 1000.0f;

            float mbps =
                (bytesSent * 8.0f) /
                (elapsed * 1000000.0f);

            Serial.print("[PROGRESS] ");

            Serial.print(
                bytesSent / 1048576.0f,
                2
            );

            Serial.print(" / 100 MiB | ");

            Serial.print(mbps, 2);
            Serial.println(" Mbit/s");

            lastProgressMs = millis();
        }
    }

    delay(100);
    uint32_t elapsedMs = millis() - startMs;

    // Blocking send() normally waits for SEND_OK.
    // The receiver remains our primary measurement.
    Serial.println("[TCP] Closing socket...");

    disconnect(SOCKET_NUMBER);
    close(SOCKET_NUMBER);

    float elapsedSeconds =
        elapsedMs / 1000.0f;

    float throughputMbps =
        elapsedSeconds > 0
            ? (bytesSent * 8.0f) /
              (elapsedSeconds * 1000000.0f)
            : 0.0f;

    Serial.println();
    Serial.println("============== RESULTS ==============");

    Serial.print("Status: ");
    Serial.println(failed ? "FAILED" : "COMPLETED");

    Serial.print("Bytes sent: ");
    Serial.println(bytesSent);

    Serial.print("Elapsed time: ");
    Serial.print(elapsedSeconds, 3);
    Serial.println(" seconds");

    Serial.print("Throughput: ");
    Serial.print(throughputMbps, 3);
    Serial.println(" Mbit/s");

    Serial.print("Send calls: ");
    Serial.println(sendCalls);

    Serial.print("Busy calls: ");
    Serial.println(busyCalls);

    Serial.print("Total send() time: ");
    Serial.print(
        (double)totalSendUs / 1000.0,
        2
    );
    Serial.println(" ms");

    Serial.println("=====================================");
}

// ============================================================
// SETUP
// ============================================================

void setup() {
    Serial.begin(115200);
    delay(2000);

    Serial.println();
    Serial.println("======================================");
    Serial.println(" CRYOPHONE HARDWARE TCP BENCHMARK");
    Serial.println(" RP2350 + W5500 + SPI1");
    Serial.println("======================================");

#if BENCH_MODE == BENCH_AES_GCM
    runChaChaBenchmark();
    Serial.println("[SETUP] Encryption test finished.");
    return;
#elif BENCH_MODE == BENCH_RAW_TCP
    prepareBuffer();

    if (!initializeW5500()) {
        Serial.println("[FATAL] W5500 initialization failed.");
        return;
    }

    delay(1000);

    runBenchmark();

    Serial.println();
    Serial.println("[SETUP] Benchmark complete.");

    Serial.println("===== DRIVER TIMING (us) =====");

    Serial.print("State: ");
    Serial.println((unsigned long long)bench_state_us);

    Serial.print("TX free: ");
    Serial.println((unsigned long long)bench_free_us);

    Serial.print("SPI data: ");
    Serial.println((unsigned long long)bench_spi_us);

    Serial.print("SEND: ");
    Serial.println((unsigned long long)bench_send_us);

    Serial.print("Calls: ");
    Serial.println(bench_calls);

    Serial.print("Burst time (us): ");
    Serial.println((uint32_t)(bench_burst_us / 1000));
    Serial.println("(Value above is milliseconds)");

    Serial.print("Burst calls: ");
    Serial.println(bench_burst_calls);

    Serial.print("Burst bytes: ");
    Serial.println((uint32_t)bench_burst_bytes);

    Serial.print("Small bursts: ");
    Serial.println(burstSmall);

    Serial.print("Medium bursts: ");
    Serial.println(burstMedium);

    Serial.print("Large bursts: ");
    Serial.println(burstLarge);

    Serial.println("[SETUP] Reset to run again.");
#else
#error "Invalid BENCH_MODE"
#endif
}

void loop() {
    delay(1000);
}
