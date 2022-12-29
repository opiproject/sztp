import http.server, ssl, socketserver

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="/my_cert.pem", keyfile="/private_key.pem")
context.load_verify_locations(cafile="/opi.pem")
handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("", 443), handler) as httpd:
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        httpd.serve_forever()
