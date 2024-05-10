from http.server import HTTPServer, BaseHTTPRequestHandler

class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Hello, World!</h1></body></html>")

def run_server():
    server_address = ("", 80)
    httpd = HTTPServer(server_address, SimpleHTTPRequestHandler)
    print("Server started on port 80...")
    httpd.serve_forever()

if __name__ == "__main__":
    run_server()
