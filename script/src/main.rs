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
use witness::assemble_witness;

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

    // -----------------------------------------------------------------------
    // 3. Assemble the TLS witness.
    // -----------------------------------------------------------------------

    let km = kx_captured
        .lock()
        .unwrap()
        .take()
        .context("KeyMaterial not captured — handshake did not complete?")?;

    let secrets = secrets_arc.lock().unwrap().clone();
    let hs_secret = secrets
        .server_hs_traffic_secret
        .context("SERVER_HANDSHAKE_TRAFFIC_SECRET not captured")?;

    eprintln!(
        "debug: inbound={} bytes, outbound={} bytes, hs_secret={} bytes",
        stream.inbound.len(),
        stream.outbound.len(),
        hs_secret.len()
    );

    let tls_witness = assemble_witness(
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
