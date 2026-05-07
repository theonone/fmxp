# FMXP (Framed Message eXchange Protocol)

> Version 0.1, __FMXP_VERSION 1

**FMXP** is a lightweight, TCP-based protocol for efficient, secure, and easy-to-use bidirectional communication between clients and servers.

It is designed for application-level communication, prioritizing simplicity, performance, and strong encryption.

> ⚠️ FMXP is **not suitable for web use cases** (e.g. browsers). It requires secure distribution of the server’s public key. If an attacker replaces this key, encryption is compromised.

---

## ✨ Features

- Simple and minimal API
- Low protocol overhead (52 bytes per frame, 24 without encryption)
- AES-256-GCM authenticated encryption, RSA-2048 OAEP encrypted key exchange
- Flexible request-response routing
- Epoll-based high-performance I/O
- Good security out of the box without certificates, but with some tradeoffs

---

## 🚀 Quick Examples

### Server

```cpp
#include <iostream>
#include "Server.hpp"

int main() {
  std::string privKey = ...; // generate via fmxp::generateRSAKeyPair() from core/enc/rsa.hpp

  fmxp::Server server(8080, privKey, 8, 1024, 64 * 1024);

  server.route("/echo",
    [](fmxp::Request& req, const fmxp::Responder& responder) {
      responder.respond(fmxp::Response(req, req.data()));
    });

  server.route(
    [](const fmxp::Request& req) {
      return req.path().starts_with("/double/");
    },
    [](fmxp::Request& req, const fmxp::Responder& responder) {
      int n = std::stoi(req.path().substr(8));
      responder.respond(fmxp::Response(req, std::to_string(n * 2)));
    });

  // fallback route
  server.route(
    [](const fmxp::Request&) { return true; },
    [](fmxp::Request& req, const fmxp::Responder& responder) {
      responder.respond(fmxp::Response(req, "", fmxp::STATUS_NOT_FOUND));
    });

  server.listen();
}
````

---

### Client

```cpp
#include <iostream>
#include "Connection.hpp"

using namespace fmxp;

int main() {
  std::string pubKey = ...;

  Connection connection(
    "127.0.0.1",
    8080,
    pubKey,
    64 * 1024,
    [](const Response& r) {
      if (r.status() == STATUS_NOT_FOUND) {
        std::cout << "Route not found\n";
        return;
      }

      std::cout << r.path() << ", " << r.data().toString() << std::endl;
    });

  connection.send(Request("/echo", "hello"));
}
```

---

## 🧠 Core Concepts

* **Frame** - the unit of communication in FMXP (request, response, etc.)
* **Request** - a frame sent by the client
* **Response** - a frame sent by the server
* **Route** - a rule to process requests like URL in HTTP

---

## 📦 Frame Structure

```
fmxp<version:1B>
     <size:8B>
     <timestamp:4B>
     <f_id:4B>
     <flags:1B>
     <status:1B>
     <path_len:2B>
     <path>
     <data>
```

- *:xB - size of the field in bytes
- Path is a variable-length field, the length is specified in `path_len` (65535 bytes max)
- Data is also a variable-length field, the length of which is (`size` - `path_len` - (4+4+1+1+2 = 12)) bytes 

* **fmxp** → protocol identifier
* **version** → protocol version (must match exactly)
* **size** → total size of the following data. Every field after this one is encrypted. The field is a 64-bit unsigned integer, so the max possible frame size is 16 exabytes
* **timestamp** → UNIX UTC timestamp for replay protection
* **f_id** → request/response identifier
* **flags** → protocol-level flags
* **status** → status code (0–255). There are standard status codes, but you can define your own
* **path_len** → length of the path (0–65535)
* **path** → route identifier
* **data** → frame data (`fmxp::ByteBuffer`)

---

## 🔐 Connection & Encryption

FMXP uses hybrid encryption:

1. Server has a **pinned RSA key pair**
2. Client securely obtains the **public key**
3. Client:
   * Generates an AES-256-GCM key
   * Encrypts it with the server’s public key
   * Sends it to the server
4. Server:
   * Decrypts the AES key using its private key
   * Stores it for the session
   * Encrypts a success message with the AES key
   * Sends it to the client
5. Client decrypts the success message with the AES key, verifies integrity
6. Handshake finishes, all further communication uses AES encryption

---

## ⏱️ Replay Protection

* Each frame includes a timestamp
* Frames older than **60 seconds** are rejected
* Helps prevent replay attacks

> ⚠️ Requires reasonably synchronized system clocks

---

## 🖥️ Server Module

### Class: `Server`

* Uses `epoll` for I/O
* Uses a thread pool for request handling

### Routing

```cpp
server.route("/path", handler);
```

Routing rules:

* String routes are checked first (exact match)
* Functional routes are checked in order of addition
* First match wins

### Execution Model

* Handlers run in the thread pool
* Multiple requests are processed in parallel

### Start Server

```cpp
server.listen(); // blocking
```

---

## 💻 Client Module

### Class: `Connection`

* Connects immediately upon construction
* Listener runs on a separate thread (non-blocking)

### Sending

```cpp
connection.send(Request("/path", "data"));
```

### Receiving

Handled via callback passed to constructor.

---

## ⚙️ Concurrency Model

* Requests are processed in parallel
* Responses are matched via `f_id`
* No global ordering guarantee across requests

---

## ❗ Error Handling

* **Invalid frame** → connection closed
* **Decryption failure** → connection closed
* **Expired frame** → connection closed
* **Route not found** → `STATUS_NOT_FOUND` response

---

## 🔒 Security Notes

* AES-256-GCM ensures:

  * Confidentiality
  * Integrity (authentication)

* RSA-2048 is used only for key exchange

### Critical Limitation

FMXP does **not** provide secure RSA key distribution.

If an attacker replaces the server’s public key in the client, security might be compromised

> Always ensure secure delivery of the public key.

---

## ⚠️ Limitations

* Not suitable for browsers or web environments
* No built-in PKI or certificate system
* No HTTP compatibility
* No guaranteed request ordering
* Linux-only (uses epoll)

---

## 🛠️ Build & Dependencies

* Modern C++ compiler
* OpenSSL (RSA + AES)
* Linux environment

---

## 🔢 Versioning

* Frames include a version field
* No backward compatibility guarantees

---

## 📈 Performance Notes

* Overhead:

  * 52 bytes (encrypted)
  * 24 bytes (unencrypted)
* Buffered I/O ensures only complete frames are processed
* Epoll enables scalable connection handling

---

## 📜 License

GNU General Public License v3

---

## 🔮 Future Plans

* Improved error handling
* Optional insecure mode (e.g. for IPC)
* Synchronous request API (`Connection.request(...)`)
* One-time request API (like requests.get(...) in Python)
* Additional security features
