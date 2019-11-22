import string

# Defines
CMP_SUCCS = ["strcmp", "memcmp", "strncmp", "strlcmp", "strcasecmp", "strncasecmp", "strstr"]
NETWORK_KEYWORDS = ["QUERY_STRING", "username", "HTTP_", "REMOTE_ADDR", "boundary=", "Content-Type", "Content-Length", "http_", "http", "HTTP", "query", "remote", "user-agent", "soap", "index."]
CASE_SENS_NETWORK_KEYWORDS = ["GET", "POST", "PUT", "DELETE", "HEAD"]

MIN_STR_LEN = 3
STR_LEN = 255
ALLOWED_CHARS = string.digits + string.ascii_letters + '-/_'
EXTENDED_ALLOWED_CHARS = ALLOWED_CHARS + "%,.;+=_)(*&^%$#@!~`|<>{}[]"


def populate_symbol_table(p):
    """
    Populate a binary symbol table, if present

    :param p: angr project
    :return: None
    """

    buckets = p.loader.main_object.hashtable.buckets + p.loader.main_object.hashtable.chains
    symtab = p.loader.main_object.hashtable.symtab
    names = [symtab.get_symbol(n).name for n in buckets]
    names = list(set([str(n) for n in names if n]))

    for name in names:
        # this will provoke symbol table to be populated
        [x for x in p.loader.find_all_symbols(name)]
