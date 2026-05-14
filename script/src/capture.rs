use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};
use x25519_dalek::{PublicKey, StaticSecret};

/// The key material captured during the TLS handshake.
#[derive(Clone)]
pub struct KeyMaterial {
    /// Client ephemeral X25519 private key (32 bytes).
    /// Passed to the SP1 guest so it can recompute X25519 → HKDF → traffic keys.
    pub client_private: [u8; 32],

    /// Server ephemeral X25519 public key (32 bytes), taken from ServerHello key_share.
    pub server_public: [u8; 32],
}

/// A `SupportedKxGroup` that performs standard X25519 but captures both
/// the client private key and the server public key after `complete()` is called.
///
/// Wire it into a `CryptoProvider` with `make_provider()` and read the result
/// from the shared `Arc<Mutex<Option<KeyMaterial>>>` after the handshake.
pub struct CapturingKxGroup {
    pub captured: Arc<Mutex<Option<KeyMaterial>>>,
}

impl fmt::Debug for CapturingKxGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CapturingKxGroup(X25519)")
    }
}

impl SupportedKxGroup for CapturingKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        // Use StaticSecret (not EphemeralSecret) so we can call to_bytes() later.
        // This is intentional — we need the private key for the ZK witness.
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        Ok(Box::new(CapturingActiveKx {
            secret,
            public,
            captured: self.captured.clone(),
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct CapturingActiveKx {
    secret: StaticSecret,
    public: PublicKey,
    captured: Arc<Mutex<Option<KeyMaterial>>>,
}

impl ActiveKeyExchange for CapturingActiveKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let server_pub_bytes = <[u8; 32]>::try_from(peer_pub_key)
            .map_err(|_| Error::General("X25519: peer key must be 32 bytes".into()))?;

        let server_pub = PublicKey::from(server_pub_bytes);
        let shared = self.secret.diffie_hellman(&server_pub);

        *self.captured.lock().unwrap() = Some(KeyMaterial {
            client_private: self.secret.to_bytes(),
            server_public: server_pub_bytes,
        });

        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

// ---------------------------------------------------------------------------
// CapturingStream
// ---------------------------------------------------------------------------

/// Wraps a `TcpStream` and records every raw byte that passes through it
/// in both directions, before rustls sees or processes them.
///
/// `inbound`  — bytes received from the server (server → client TLS records)
/// `outbound` — bytes sent by the client (client → server TLS records)
///
/// After the TLS connection is complete, these buffers contain the full
/// wire transcript used to reconstruct the handshake for the ZK witness.
pub struct CapturingStream {
    inner: TcpStream,
    pub inbound: Vec<u8>,
    pub outbound: Vec<u8>,
}

impl CapturingStream {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            inner: stream,
            inbound: Vec::new(),
            outbound: Vec::new(),
        }
    }
}

impl Read for CapturingStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.inbound.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl Write for CapturingStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.outbound.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

// rustls needs `Read + Write + ?Sized` — blanket impls handle that.
// But `StreamOwned` also requires the IO type to be Send, which TcpStream is.

/// Build a `CryptoProvider` that uses our capturing X25519 group and
/// falls back to ring for everything else (cipher suites, signatures, etc).
///
/// The `captured` arc will be populated with `KeyMaterial` once the
/// TLS handshake completes.
pub fn make_capturing_provider(
    captured: Arc<Mutex<Option<KeyMaterial>>>,
) -> rustls::crypto::CryptoProvider {
    // Box::leak gives us a &'static reference, which CryptoProvider requires.
    // This leaks one allocation per connection — acceptable for our use case.
    let kx: &'static dyn SupportedKxGroup = Box::leak(Box::new(CapturingKxGroup { captured }));

    rustls::crypto::CryptoProvider {
        kx_groups: vec![kx],
        ..rustls::crypto::ring::default_provider()
    }
}
