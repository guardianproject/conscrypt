;; This buffer is for text that is not saved, and for Lisp evaluation.
;; To create a file, visit it with C-x C-f and enter text in its buffer.


# Implementation of HTTP Transport Authentication

As explained in Section 2 of the standards draft <draft-schinazi-httpbis-transport-auth>, the idea
is to leverage auxiliary elements of the TLS handshake (which, under normal HTTPS
circumstances, are lost once the connection is in place at the application/SecureSocket level) to
allow security information to be exchanged and later used in authenticating the connection at
the HTTP level with HTTP’s CONNECT verb. Unlike normal HTTP authentication, this
authentication takes place only once for a given session - at connect-time. Normal HTTP
authentication is “per request”. A signature element of this addition to HTTP is that it “fails
silently” - if the application attempts to CONNECT to a server supporting this mechanism without
using Transport Auth, or if the application submits wrong data, the server will fail with that same
error codes reserved for “normal” HTTP CONNECT. Thus, support for HTTP Transport
Authentication is “invisible” to probing applications.

NOTE: The mechanism by which the “auxiliary elements” of the TLS handshake are available
and exported is already standardized, and in a generic and extensible manner. This is
supported in OpenSSL and BoringSSL such that virtually all implementations of both client and
server HTTP stacks include at minimum access to the primitives.

## Acquiring the “Auxiliary Elements” of the TLS Handshake - SSL

The SSL implementation libraries contain a function SSL_export_keying_material() that
does the heavy lifting, deriving a new secret from the TLS master secret in use for the current
connection (and, itself, only used by the low-level connection). This method takes, as input,
const char *label - a string defining (effectively) the use for the derived material. This
variable lets the function create many external-use secrets. Section 7.3 of the draft indicates the
proper value to use for *label, allowing the client and server to “rendezvous” using the same
derived key.

NOTE: The draft - a standards track document - must discuss when it will require IANA to be
involved with “broadly agreed constants”. However, in practice, it’s possible for implementation
software to use other constants - NOT listed in IANA documents - to rendezvous. In practice,
the label string is hashed internally and obviously ANY provided string would be hashed
similarly. At this point in our work, this option is not necessary...but available if we wish to define
a new HTTP authentication scheme for example.

## Acquiring the “Auxiliary Elements” of the TLS Handshake - Conscrypt

Google’s Conscrypt NativeCrypto.java (source link) “provides the Java side of our JNI glue for
OpenSSL” (line 48). On line 963, we see the glue for SSL_export_keying_material().
The higher-level method, exportKeyingMaterial(), is in Conscrypt.java on line 491.

## Source Code

The already-completed source code for this project is located in the MASQUE Implementation
“Ali Final Documents and Code” sub-folder in the file
ACT2-Complete-20210107T015946Z-001.zip.

## Initial Implementation

In the original implementation by Ali Hussain), the modifications to Conscrypt are in source
subdirectories:

```
conscrypt-transportauth: server-side
conscrypt-transportauthclient: client-side
```

##  Client Implementation

See subdirectory src/main/java/com/example/conscrypt_transportauthclient.
File HTTPSClient.java implements the client side of HTTP Transport Authentication. In fact, it
only acquires the keying material, authenticates and ends.
Operatively, notice how the run() method first establishes itself as a
`handshakeCompletedListener()`:

    this.sslSocket.addHandshakeCompletedListener(this);

This is what allows the higher level code to “pause” the TLS handshake long enough to acquire
the keying material and, in effect, this is the key modification to Conscrypt’s Java normal class
hierarchy used by programmers wanting access to HTTP-layer connections of any sort.

## Server Implementation

See subdirectory src/main/java/com/example/conscrypt_transportauth
The server implementation is functionally identical to the client in terms of key material
acquisition.
