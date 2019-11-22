FILTER = ["lib"]
CMP_SUCCS = ["strcmp", "memcmp", "strncmp", "strlcmp", "strcasecmp", "strstr"]

def populate_symbol_table(p):
    buckets = p.loader.main_object.hashtable.buckets + p.loader.main_object.hashtable.chains
    symtab = p.loader.main_object.hashtable.symtab
    names = [symtab.get_symbol(n).name for n in buckets]
    names = list(set([str(n) for n in names if n]))
    for name in names:
        # this will provoke symbol table to be populated
        [x for x in p.loader.find_all_symbols(name)]
