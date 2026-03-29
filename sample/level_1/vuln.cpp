/**
 * Demonstrates a pattern vulnerable to CVE-2012-0036.
 *
 * When linked against libcurl < 7.24.0, this program does not sanitize
 * special characters (such as CRLF) extracted from the path component
 * of a URL. An attacker can supply a URL like
 *   smtp://example.com/%0D%0AEXTRA%20COMMAND
 * and the vulnerable libcurl would decode %0D%0A, injecting a CRLF
 * into the protocol dialogue (e.g., SMTP, IMAP, POP3).
 *
 * The vulnerability is encapsulated in the function vulnerable_curl().
 */

#include <iostream>
#include <curl/curl.h>

// Minimal callback to discard data – we only care about the protocol injection
static size_t discard_data(void *buffer, size_t size, size_t nmemb, void *userp) {
    (void)buffer;
    (void)userp;
    return size * nmemb;
}

// Function that contains the vulnerable libcurl usage
void vulnerable_curl(const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Failed to initialize libcurl" << std::endl;
        return;
    }

    // Set the URL from the parameter – this is the injection vector
    curl_easy_setopt(curl, CURLOPT_URL, url);

    // For protocols like SMTP, we often need to specify a sender and recipient.
    // Here we use dummy values so the transfer can proceed.
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, "<sender@example.com>");
    struct curl_slist *recipients = nullptr;
    recipients = curl_slist_append(recipients, "<recipient@example.com>");
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

    // Provide dummy data to send (required for SMTP)
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, discard_data);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    // Optionally enable verbose output to see the actual protocol commands
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        std::cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << std::endl;
    }

    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <url>" << std::endl;
        std::cerr << "Example: " << argv[0] << " smtp://mail.example.com/%0D%0AEHLO%20attacker" << std::endl;
        return 1;
    }

    curl_global_init(CURL_GLOBAL_ALL);
    vulnerable_curl(argv[1]);
    curl_global_cleanup();

    return 0;
}