import bf.sinks as sinks

ROUND = 5

SINK_FUNCS = [('strcpy', sinks.strcpy), ('sprintf', sinks.sprintf), ('fwrite', sinks.fwrite), ('memcpy', sinks.memcpy)]
TIMEOUT_TAINT = 60 * 5
TIMEOUT_TRIES = 2
