import json
import sqlite3
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit


TOKENS = {"local-publisher": "publisher"}
PACKAGES = {}
INDEX = sqlite3.connect(":memory:")
INDEX.execute("CREATE TABLE packages (name TEXT PRIMARY KEY)")


class Registry(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/search":
            query = parse_qs(urlsplit(self.path).query).get("q", [""])[0]
            rows = INDEX.execute("SELECT name FROM packages WHERE name LIKE '%" + query + "%'").fetchall()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(rows).encode("utf-8"))
            return
        if not path.startswith("/packages/"):
            self.send_error(404)
            return
        name = path.removeprefix("/packages/")
        record = PACKAGES.get(name)
        if record is None:
            self.send_error(404)
            return
        data = json.dumps(record["metadata"]).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        path = urlsplit(self.path).path
        owner = TOKENS.get(self.headers.get("Authorization", "").removeprefix("Bearer "))
        if not owner:
            self.send_error(401)
            return
        if not path.startswith("/packages/"):
            self.send_error(404)
            return
        name = path.removeprefix("/packages/")
        if name in PACKAGES and PACKAGES[name]["owner"] != owner:
            self.send_error(403)
            return
        length = int(self.headers.get("Content-Length", "0"))
        if not 0 < length <= 8192:
            self.send_error(413)
            return
        metadata = json.loads(self.rfile.read(length))
        PACKAGES[name] = {"owner": owner, "metadata": metadata}
        INDEX.execute("INSERT OR IGNORE INTO packages(name) VALUES (?)", (name,))
        self.send_response(201)
        self.end_headers()


if __name__ == "__main__":
    HTTPServer(("localhost", 8080), Registry).serve_forever()
