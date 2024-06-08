import http.server
import socketserver
import threading

# List of ports extracted from the traffic generation script
ports = [
    80, 161, 23, 3389, 5900, 143, 110, 3306, 5432, 6379, 11211, 27017, 5672, 9200,
    9092, 2049, 587, 990, 465, 636, 88, 873, 162, 389, 5060, 520, 69, 179, 123, 49,
    1812
]

# Define a request handler class that includes the port in the response
class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.port = kwargs.pop('port')
        super().__init__(*args, **kwargs)

    def do_GET(self):
        # Create a custom message including the port number
        message = f"Hello! You have reached the server on port {self.port}"
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(bytes(message, "utf8"))

# Define a function to start the server on a given port
def start_server(port):
    Handler = lambda *args, **kwargs: MyHttpRequestHandler(*args, port=port, **kwargs)
    with socketserver.TCPServer(("", port), Handler) as httpd:
        print(f"Serving HTTP on port {port}")
        httpd.serve_forever()

# Create and start a thread for each port
threads = []
for port in ports:
    thread = threading.Thread(target=start_server, args=(port,))
    threads.append(thread)
    thread.start()

# Wait for all threads to complete
for thread in threads:
    thread.join()

# Run the main function to get the DEST_IP input
def main():
    global DEST_IP
    DEST_IP = input("Enter the destination IP address: ")

if __name__ == "__main__":
    main()
