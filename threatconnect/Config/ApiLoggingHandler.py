from logging import FileHandler, LogRecord
from threatconnect.RequestObject import RequestObject


def create_log_entry(record):
    log_entry = {}

    if hasattr(record, 'asctime'):
        log_entry['timestamp'] = record.asctime

    if hasattr(record, 'msg'):
        log_entry['message'] = record.msg

    if hasattr(record, 'levelname'):
        log_entry['level'] = record.levelname

    return log_entry


class ApiLoggingHandler(FileHandler):
    """ Extension of FileHandler; used to send log entries to the api """

    def __init__(self, filename, tc, max_entries_before_flush=100):
        super(ApiLoggingHandler, self).__init__(filename)
        self.tc = tc
        self.entries = []
        self.max_entries_before_flush = max_entries_before_flush;

    def emit(self, record):
        entry = create_log_entry(record)

        # if we've reached the max_entries threshold, flush the handler
        if len(self.entries) > self.max_entries_before_flush:
            self.flush()
            self.entries = []

        self.entries.append(entry)
        super(ApiLoggingHandler, self).emit(record)

    def flush(self):
        # make api call
        ro = RequestObject()
        ro.set_http_method('POST')
        ro.set_owner_allowed(True)
        ro.set_resource_pagination(False)
        ro.set_request_uri('/v2/logs/app')
        ro.set_body(self.entries)

        # retrieve and display the results
        try:
            self.tc.api_request(ro)
        except RuntimeError as re:
            # can't really do anything if it fails
            lr = LogRecord(level='ERROR',
                           msg='API LOGGING FAILURE -- Unable to send log entries to api: {}'.format(self.entries))
            self.entries = []
            self.emit(lr)

        super(ApiLoggingHandler, self).flush()
