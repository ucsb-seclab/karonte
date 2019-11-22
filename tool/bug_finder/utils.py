import sinks

ROUND = 5

HTTP_KEYWORDS = ("boundary=", "Content-Type", "http_")
SINK_FUNCS = [('strcpy', sinks.strcpy), ('sprintf', sinks.sprintf), ('fwrite', sinks.fwrite), ('memcpy', sinks.memcpy)]
TIMEOUT_TAINT = 60 * 5
TIMEOUT_TRIES = 2
