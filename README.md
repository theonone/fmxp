# FMXP (Framed Message eXchange Protocol)

> Version 0.1.2, `__FMXP_VERSION 1`

**FMXP** is a lightweight TCP-based protocol for efficient, secure, and easy-to-use bidirectional communication between clients and servers.

It is designed for application-level communication, prioritizing simplicity, performance, and strong encryption.

> ⚠️ FMXP is **not suitable for browsers or traditional web use cases**. It relies on secure distribution of the server’s public RSA key. If an attacker replaces this key, encryption may be compromised.

---

# ✨ Features

* Simple and minimal API
* Low protocol overhead
  * 56 bytes encrypted
  * 28 bytes unencrypted
* AES-256-GCM authenticated encryption
* RSA-2048 OAEP encrypted key exchange
* Built-in replay protection
* Epoll-based high-performance networking
* Thread pool request handling
* Flexible request-response routing
* Server push support
* Strong encrypted transport without TLS or certificates

---

# 🚀 Quick Examples

## Server

```cpp
#include <iostream>

#include "Server.hpp"

int main() {
  std::string privKey = ...;

  fmxp::Server server(8080, privKey, 8, 1024, 64 * 1024);

  server.route(
      "/echo",
      [](fmxp::Request& req, const fmxp::Responder& responder) {
        responder.respond(req, req.data(), fmxp::STATUS_OK);
      });

  server.route(
      [](const fmxp::Request& req) {
        if (req.path().substr(0, 8) == "/double/" &&
            req.path().length() > 8) {
          try {
            std::stoi(req.path().substr(8));
            return true;
          } catch (...) {
            return false;
          }
        }

        return false;
      },

      [](fmxp::Request& req, const fmxp::Responder& responder) {
        int n = std::stoi(req.path().substr(8));

        responder.respond(
            req,
            std::to_string(n * 2),
            fmxp::STATUS_OK);
      });

  server.route(
      [](const fmxp::Request&) { return true; },

      [](fmxp::Request& req,
         const fmxp::Responder& responder) {
        responder.respond(
            req,
            "",
            fmxp::STATUS_NOT_FOUND);
      });

  server.setOnError(
      [](uint8_t code, const std::string& message) {
        std::cout << "Error: "
                  << (int)code
                  << ": "
                  << message
                  << std::endl;

        return true;
      });

  server.listen();

  return 0;
}
```

---

## Client

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
          std::cout << "Route not found"
                    << std::endl;
          return;
        }

        std::cout
            << r.path()
            << ", "
            << r.data().toString()
            << std::endl;
      });

  connection.setOnClose([]() {
    std::cout << "Connection closed!"
              << std::endl;

    exit(0);
  });

  while (true) {
    std::string line;

    std::getline(std::cin, line);

    if (line == "exit") {
      connection.close();

      std::cout << "Connection closed"
                << std::endl;

      break;
    }

    if (line.substr(0, 5) == "send ") {
      std::string args = line.substr(5);

      size_t whitespace = args.find(' ');

      if (whitespace == std::string::npos) {
        std::cout << "Invalid command"
                  << std::endl;

        continue;
      }

      std::string path =
          args.substr(0, whitespace);

      std::string data =
          args.substr(whitespace + 1);

      if (!connection.send(path, data)) {
        std::cout << "Send failed!"
                  << std::endl;

        break;
      }

      continue;
    }

    std::cout << "Unknown command"
              << std::endl;
  }

  return 0;
}
```

---

# 🧠 Core Concepts

| Concept  | Description                                   |
| -------- | --------------------------------------------- |
| Frame    | Unit of communication in FMXP                 |
| Request  | Client-to-server frame                        |
| Response | Server-to-client frame                        |
| Route    | Request processing rule                       |
| RID      | Request ID for request-response matching      |
| FID      | Monotonic frame ID used for replay protection |
| SSID     | Session ID used for replay protection         |

---

# 📦 Frame Structure

```text
fmxp<version:1B>
     <size:4B>
     <rid:4B>
     <fid:4B>
     <ssid:8B>
     <flags:1B>
     <status:1B>
     <path_len:2B>
     <path>
     <data>
```

* `path` is variable-length (`0–65535` bytes)
* `data` is variable-length
* `size` is the encrypted body size in bytes
* Maximum frame size is implementation-defined and configurable, the hard cap is 4GB

---

## Field Descriptions

| Field      | Description          |
| ---------- | -------------------- |
| `fmxp`     | Protocol identifier  |
| `version`  | Protocol version     |
| `size`     | Encrypted body size  |
| `rid`      | Request ID           |
| `fid`      | Monotonic frame ID   |
| `ssid`     | Session ID           |
| `flags`    | Protocol-level flags |
| `status`   | Status code          |
| `path_len` | Path length          |
| `path`     | Route identifier     |
| `data`     | Frame payload        |

---

# 🔐 Connection & Encryption

FMXP uses hybrid encryption.

## Handshake

1. Server owns a pinned RSA-2048 key pair
2. Client securely obtains the public key
3. Client:

   * Generates an AES-256-GCM key
   * Appends the current UTC UNIX timestamp
   * Encrypts payload with RSA-OAEP
   * Sends it to the server
4. Server:

   * Decrypts payload
   * Validates timestamp (must be younger than 60 seconds)
   * Stores AES key
   * Generates unique session ID (SSID)
   * Encrypts success message using AES
   * Sends SSID to the client
5. Client:

   * Verifies decrypted success message
   * Extracts SSID
6. Secure session begins

All further communication uses AES-256-GCM.

---

# ⏱️ Replay Protection

FMXP includes built-in replay protection.

## Handshake Replay Protection

Handshake payloads contain a UNIX timestamp.

The server rejects handshake payloads older than 60 seconds.

This prevents replaying previously captured AES keys.

---

## Session Replay Protection

Each session includes:

* Unique SSID
* Monotonically increasing FID values

Both client and server validate:

* SSID must match the active session
* FID must always be greater than the previously received FID

Invalid replay state immediately terminates the connection.

Replay protection is automatic and fully internal to the library. If you see an error related to that, either the connection is attacked, or I messed up

---

# 🔑 RSA Key Generation

FMXP requires an RSA-2048 key pair compatible with the protocol’s encryption implementation.

The recommended way to generate keys is using the built-in helper from:

```cpp
#include "core/enc/rsa.hpp"
```

---

## Generate Key Pair

```cpp
auto keys = fmxp::generateRSAKeyPair();

std::string publicKey = keys.public_key;
std::string privateKey = keys.private_key;
```

The generated keys are:

* RSA-2048
* PEM encoded
* Compatible with FMXP RSA-OAEP encryption

> ⚠️ Using externally generated keys may lead to incompatibility if the format or parameters differ from FMXP expectations.

---

# 🖥️ Server API

## Class: `Server`

```cpp
Server(
    int port,
    std::string privKey,
    size_t workerThreads,
    int maxConnections = 1024,
    int maxFrameSize = 64 * 1024
);
```

Creates and configures an FMXP server.

---

## Constructor Parameters

| Parameter        | Description                          |
| ---------------- | ------------------------------------ |
| `port`           | TCP port to listen on                |
| `privKey`        | RSA private key                      |
| `workerThreads`  | Number of thread pool workers        |
| `maxConnections` | Maximum simultaneous connections     |
| `maxFrameSize`   | Maximum accepted frame size in bytes |

---

## Exact Route

```cpp
server.route("/path", handler);
```

Registers an exact-match route.

Example:

```cpp
server.route(
    "/echo",

    [](fmxp::Request& req,
       const fmxp::Responder& responder) {

      responder.respond(
          req,
          req.data(),
          fmxp::STATUS_OK);
    });
```

---

## Functional Route

```cpp
server.route(matcher, handler);
```

Registers a dynamic route.

The matcher decides whether the handler should process the request.

Example:

```cpp
server.route(
    [](const fmxp::Request& req) {
      return req.path() == "/hello";
    },

    [](fmxp::Request& req,
       const fmxp::Responder& responder) {

      responder.respond(
          req,
          "world",
          fmxp::STATUS_OK);
    });
```

---

## Routing Rules

* Exact routes are checked first
* Functional routes are checked in insertion order
* First successful match wins

---

## Start Listening

```cpp
server.listen();
```

Starts the server loop.

This call blocks the current thread.

---

## Stop Server

```cpp
server.stop();
```

Stops the server.

---

## Send Response Manually

```cpp
server.sendResponse(response);
```

Manually send a `Response`.

Usually unnecessary because handlers should use `Responder`.

---

## Close Connection

```cpp
server.closeConnection(connectionID);
```

Forcefully closes a client connection.

---

## Error Handler

```cpp
server.setOnError(callback);
```

Registers a custom error handler.

Example:

```cpp
server.setOnError(
    [](uint8_t code,
       const std::string& message) {

      std::cout
          << "Error: "
          << (int)code
          << ": "
          << message
          << std::endl;

      return true;
    });
```

If the callback returns `false`,
the default FMXP error handler executes afterwards.

---

# 📨 Responder API

Route handlers receive a `Responder` object.

```cpp
void(Request&, const Responder&)
```

Responder provides helper methods for interacting with connections.

---

## Respond To Request

```cpp
responder.respond(req, data, status);
```

Sends a response matching the request.

Parameters:

| Parameter | Description          |
| --------- | -------------------- |
| `req`     | Original request     |
| `data`    | Response payload     |
| `status`  | Response status code |

Example:

```cpp
responder.respond(
    req,
    "pong",
    fmxp::STATUS_OK);
```

---

## Server Push

```cpp
responder.serverPush(
    connectionID,
    path,
    data,
    status
);
```

Sends a server-initiated frame without a request.

Parameters:

| Parameter      | Description   |
| -------------- | ------------- |
| `connectionID` | Target client |
| `path`         | Route/path    |
| `data`         | Payload       |
| `status`       | Status code   |

Example:

```cpp
responder.serverPush(
    req.connectionID(),
    "/notification",
    "hello",
    fmxp::STATUS_OK);
```

---

## Close Connection

```cpp
responder.close(connectionID);
```

Immediately closes a client connection.

Example:

```cpp
responder.close(req.connectionID());
```

---

# 💻 Client API

## Class: `Connection`

```cpp
Connection(
    const std::string& host,
    int port,
    const std::string& pubKey,
    uint32_t maxFrameSize,
    std::function<void(const Response&)> onResponse
);
```

Creates a connection and immediately connects to the server.

The listener runs on a separate thread.

---

## Constructor Parameters

| Parameter      | Description                 |
| -------------- | --------------------------- |
| `host`         | Server IP/hostname          |
| `port`         | Server port                 |
| `pubKey`       | Server RSA public key       |
| `maxFrameSize` | Maximum accepted frame size |
| `onResponse`   | Response callback           |

---

## Response Callback

The callback receives all server responses.

Example:

```cpp
[](const Response& r) {
  std::cout
      << r.path()
      << ": "
      << r.data().toString()
      << std::endl;
}
```

---

## Send Simple Request

```cpp
connection.send(path, data);
```

Example:

```cpp
connection.send("/echo", "hello");
```

Returns `false` if the connection is closed.

---

## Send Custom Request

```cpp
connection.sendReq(request);
```

Allows sending a manually constructed `Request`.

Example:

```cpp
Request req(
    "/hello",
    "world"
);

connection.sendReq(req);
```

---

## Set Response Callback

```cpp
connection.setOnResponse(callback);
```

Changes the response handler after construction.

---

## Set Close Callback

```cpp
connection.setOnClose(callback);
```

Registers a callback called when the connection closes.

Example:

```cpp
connection.setOnClose([]() {
  std::cout << "Disconnected"
            << std::endl;
});
```

---

## Close Connection

```cpp
connection.close();
```

Closes the connection gracefully.

---

# ⚙️ Concurrency Model

* Requests process in parallel
* RID values are used for request-response matching (TODO)
* FID values are used exclusively for replay protection

---

# ❗ Error Handling

| Error                | Result             |
| -------------------- | ------------------ |
| Invalid frame        | Connection closed  |
| Decryption failure   | Connection closed  |
| Invalid replay state | Connection closed  |
| Route not found      | `STATUS_NOT_FOUND`* |

<p>* - unless you add a catch-all route</p> 

---

# 🔒 Security Notes

## AES-256-GCM Provides

* Confidentiality
* Integrity
* Authentication

---

## RSA-2048 Usage

RSA is used only for key exchange.

All normal communication uses AES-256-GCM.

---

## Replay Protection

FMXP protects against:

* Replaying captured frames
* Reusing old AES handshake payloads
* Injecting frames into another session
* Replaying old server responses

Replay validation is enforced on both client and server.

---

## Critical Limitation

FMXP does not provide secure public key distribution.

If an attacker replaces the server’s public key in the client, security may be compromised.

Always securely distribute and pin the public key.

---

# ⚠️ Limitations

* Linux-only (`epoll`)
* No browser compatibility
* No built-in PKI or certificate system
* No HTTP compatibility
* No guaranteed request ordering

---

# 🛠️ Build & Dependencies

Requirements:

* Modern C++ compiler
* OpenSSL
* Linux environment

---

# 🔢 Versioning

* Every frame includes a protocol version
* Exact version matching is required
* No backward compatibility guarantees currently exist

---

# 📈 Performance Notes

* Low protocol overhead
* Buffered frame parsing
* Only complete frames are processed
* Epoll-based scalable networking
* Thread pool request execution

---

# 📜 License

GNU General Public License v3

---

# 🔮 Future Plans

* Optional insecure mode (e.g. IPC)
* Synchronous request API
* One-shot request API
