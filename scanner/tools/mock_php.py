import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('X-Powered-By','PHP/8.3.2')
        self.send_header('Server','Apache/2.4.57 (Debian)')
        self.send_header('Content-Type','text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(b"<!doctype html><html lang=ca><head><meta charset=utf-8>"
                         b"<title>Botiga PHP (demo)</title></head><body>"
                         b"<h1>Botiga de demostracio</h1>"
                         b"<p>Servidor PHP d'exemple per provar la deteccio de PHP2Shell.</p>"
                         b"</body></html>")
    def log_message(self,*a): pass
http.server.HTTPServer(('127.0.0.1',5090),H).serve_forever()
