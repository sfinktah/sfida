def ida_issue():
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from socketserver import ThreadingMixIn
    import threading

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()

    class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
        allow_reuse_address = True

    class Worker(threading.Thread):
        def __init__(self, host, port):
            threading.Thread.__init__(self)
            self.httpd = ThreadedHTTPServer((host, port), Handler)
            self.host = host
            self.port = port

        def run(self):
            self.httpd.serve_forever()

        def stop(self):
            self.httpd.shutdown()
            self.httpd.server_close()

    class Master:
        def __init__(self):
            self.worker = Worker('127.0.0.1', 28612)
            self.worker.start()

    def main():
        master = Master()
        return master

    return main()

server = ida_issue()
