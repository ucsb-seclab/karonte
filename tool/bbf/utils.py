import string

# Defines
CMP_SUCCS = ["strcmp", "memcmp", "strncmp", "strlcmp", "strcasecmp", "strncasecmp", "strstr"]
NETWORK_KEYWORDS = ["QUERY_STRING", "username", "http_", "REMOTE_ADDR", "boundary=",
                    "HTTP_", "query", "remote", "user-agent", "soap", "index.", "CONTENT_TYPE", "Content-Type"]
CASE_SENS_NETWORK_KEYWORDS = ["GET", "POST", "PUT", "DELETE", "HEAD"]
N_TYPE_DATA_KEYS = 4

MIN_STR_LEN = 3
STR_LEN = 255
ALLOWED_CHARS = f"{string.digits}{string.ascii_letters}-/_"
EXTENDED_CHARS = "%,.;+=)(*&^%$#@!~`|<>{}[]"
EXTENDED_ALLOWED_CHARS = f"{ALLOWED_CHARS}{EXTENDED_CHARS}"
SEPARATOR_CHARS = ('-', '_')