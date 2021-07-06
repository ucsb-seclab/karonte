import string

# Defines
CMP_SUCCS = ["strcmp", "memcmp", "strncmp", "strlcmp", "strcasecmp", "strncasecmp", "strstr"]
NETWORK_KEYWORDS = ["QUERY_STRING", "username", "http_", "REMOTE_ADDR", "boundary=",
                    "HTTP_", "query", "remote", "user-agent", "soap", "index.", "CONTENT_TYPE", "Content-Type"]
# those keywords are used to speed up the analysis and only allow datakeys that contain at least one of these words
# to prevent large 1000+ roles to analyze
EXTENDED_NETWORK_KEYWORDS = ["ip", "http", "dns", "wan", "ssid", "soap", "user", "query", "remote"]
#"Content-Length", "http"
CASE_SENS_NETWORK_KEYWORDS = ["GET", "POST", "PUT", "DELETE", "HEAD"]
N_TYPE_DATA_KEYS = 4

MIN_STR_LEN = 3
STR_LEN = 255
ALLOWED_CHARS = f"{string.digits}{string.ascii_letters}-/_"
EXTENDED_ALLOWED_CHARS = f"{ALLOWED_CHARS}%,.;+=_)(*&^%$#@!~`|<>{{}}[]"
