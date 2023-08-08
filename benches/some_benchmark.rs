use std::fs;
use std::io::{self, Read, Write};
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use rustls::client::Resumption;
use rustls::server::{NoServerSessionStorage, ServerSessionMemoryCache, WebPkiClientVerifier};
use rustls::RootCertStore;
use rustls::Ticketer;
use rustls::{ClientConfig, ClientConnection};
use rustls::{ConnectionCommon, SideData};
use rustls::{ServerConfig, ServerConnection};

// use criterion::{black_box, Criterion, criterion_group, criterion_main};
// use criterion_perf_events::Perf;
// use perfcnt::linux::HardwareEventType as Hardware;
// use perfcnt::linux::PerfCounterBuilderLinux as Builder;
use iai::black_box;
use rustls::crypto::ring::Ring;

fn transfer<L, R, LS, RS>(left: &mut L, right: &mut R, expect_data: Option<usize>)
    where
        L: DerefMut + Deref<Target = ConnectionCommon<LS>>,
        R: DerefMut + Deref<Target = ConnectionCommon<RS>>,
        LS: SideData,
        RS: SideData,
{
    let mut tls_buf = [0u8; 262144];
    let mut data_left = expect_data;
    let mut data_buf = [0u8; 8192];

    loop {
        let mut sz = 0;

        while left.wants_write() {
            let written = left
                .write_tls(&mut tls_buf[sz..].as_mut())
                .unwrap();
            if written == 0 {
                break;
            }

            sz += written;
        }

        if sz == 0 {
            return;
        }

        let mut offs = 0;
        loop {
            match right.read_tls(&mut tls_buf[offs..sz].as_ref()) {
                Ok(read) => {
                    right.process_new_packets().unwrap();
                    offs += read;
                }
                Err(err) => {
                    panic!("error on transfer {}..{}: {}", offs, sz, err);
                }
            }

            if let Some(left) = &mut data_left {
                loop {
                    let sz = match right.reader().read(&mut data_buf) {
                        Ok(sz) => sz,
                        Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                        Err(err) => panic!("failed to read data: {}", err),
                    };

                    *left -= sz;
                    if *left == 0 {
                        break;
                    }
                }
            }

            if sz == offs {
                break;
            }
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
enum ClientAuth {
    No,
    Yes,
}

#[derive(PartialEq, Clone, Copy)]
enum ResumptionParam {
    No,
    SessionID,
    Tickets,
}

impl ResumptionParam {
    fn label(&self) -> &'static str {
        match *self {
            Self::No => "no-resume",
            Self::SessionID => "sessionid",
            Self::Tickets => "tickets",
        }
    }
}

// copied from tests/api.rs
#[derive(PartialEq, Clone, Copy, Debug)]
enum KeyType {
    Rsa,
    Ecdsa,
    Ed25519,
}

struct BenchmarkParam {
    key_type: KeyType,
    ciphersuite: rustls::SupportedCipherSuite,
    version: &'static rustls::SupportedProtocolVersion,
}

impl BenchmarkParam {
    const fn new(
        key_type: KeyType,
        ciphersuite: rustls::SupportedCipherSuite,
        version: &'static rustls::SupportedProtocolVersion,
    ) -> Self {
        Self {
            key_type,
            ciphersuite,
            version,
        }
    }
}

static ALL_BENCHMARKS: &[BenchmarkParam] = &[
    #[cfg(feature = "tls12")]
        BenchmarkParam::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        &rustls::version::TLS12,
    ),
    #[cfg(feature = "tls12")]
        BenchmarkParam::new(
        KeyType::Ecdsa,
        rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        &rustls::version::TLS12,
    ),
    #[cfg(feature = "tls12")]
        BenchmarkParam::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        &rustls::version::TLS12,
    ),
    #[cfg(feature = "tls12")]
        BenchmarkParam::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        &rustls::version::TLS12,
    ),
    #[cfg(feature = "tls12")]
        BenchmarkParam::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        &rustls::version::TLS12,
    ),
    #[cfg(feature = "tls12")]
        BenchmarkParam::new(
        KeyType::Ecdsa,
        rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        &rustls::version::TLS12,
    ),
    #[cfg(feature = "tls12")]
        BenchmarkParam::new(
        KeyType::Ecdsa,
        rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        &rustls::version::TLS12,
    ),
    BenchmarkParam::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        &rustls::version::TLS13,
    ),
    BenchmarkParam::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
        &rustls::version::TLS13,
    ),
    BenchmarkParam::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        &rustls::version::TLS13,
    ),
    BenchmarkParam::new(
        KeyType::Ecdsa,
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        &rustls::version::TLS13,
    ),
    BenchmarkParam::new(
        KeyType::Ed25519,
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        &rustls::version::TLS13,
    ),
];

impl KeyType {
    fn path_for(&self, part: &str) -> String {
        match self {
            Self::Rsa => format!("test-ca/rsa/{}", part),
            Self::Ecdsa => format!("test-ca/ecdsa/{}", part),
            Self::Ed25519 => format!("test-ca/eddsa/{}", part),
        }
    }

    fn get_chain(&self) -> Vec<rustls::Certificate> {
        rustls_pemfile::certs(&mut io::BufReader::new(
            fs::File::open(self.path_for("end.fullchain")).unwrap(),
        ))
            .unwrap()
            .iter()
            .map(|v| rustls::Certificate(v.clone()))
            .collect()
    }

    fn get_key(&self) -> rustls::PrivateKey {
        rustls::PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(
                fs::File::open(self.path_for("end.key")).unwrap(),
            ))
                .unwrap()[0]
                .clone(),
        )
    }

    fn get_client_chain(&self) -> Vec<rustls::Certificate> {
        rustls_pemfile::certs(&mut io::BufReader::new(
            fs::File::open(self.path_for("client.fullchain")).unwrap(),
        ))
            .unwrap()
            .iter()
            .map(|v| rustls::Certificate(v.clone()))
            .collect()
    }

    fn get_client_key(&self) -> rustls::PrivateKey {
        rustls::PrivateKey(
            rustls_pemfile::pkcs8_private_keys(&mut io::BufReader::new(
                fs::File::open(self.path_for("client.key")).unwrap(),
            ))
                .unwrap()[0]
                .clone(),
        )
    }
}

fn make_server_config(
    params: &BenchmarkParam,
    client_auth: ClientAuth,
    resume: ResumptionParam,
    max_fragment_size: Option<usize>,
) -> ServerConfig<Ring> {
    let client_auth = match client_auth {
        ClientAuth::Yes => {
            let roots = params.key_type.get_chain();
            let mut client_auth_roots = RootCertStore::empty();
            for root in roots {
                client_auth_roots.add(&root).unwrap();
            }
            WebPkiClientVerifier::builder(Arc::new(client_auth_roots)).build().unwrap()
        }
        ClientAuth::No => WebPkiClientVerifier::no_client_auth(),
    };

    let mut cfg = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[params.version])
        .unwrap()
        .with_client_cert_verifier(client_auth)
        .with_single_cert(params.key_type.get_chain(), params.key_type.get_key())
        .expect("bad certs/private key?");

    if resume == ResumptionParam::SessionID {
        cfg.session_storage = ServerSessionMemoryCache::new(128);
    } else if resume == ResumptionParam::Tickets {
        cfg.ticketer = Ticketer::new().unwrap();
    } else {
        cfg.session_storage = Arc::new(NoServerSessionStorage {});
    }

    cfg.max_fragment_size = max_fragment_size;
    cfg
}

fn make_client_config(
    params: &BenchmarkParam,
    clientauth: ClientAuth,
    resume: ResumptionParam,
) -> ClientConfig<Ring> {
    let mut root_store = RootCertStore::empty();
    let mut rootbuf =
        io::BufReader::new(fs::File::open(params.key_type.path_for("ca.cert")).unwrap());
    root_store.add_parsable_certificates(&rustls_pemfile::certs(&mut rootbuf).unwrap());

    let cfg = ClientConfig::builder()
        .with_cipher_suites(&[params.ciphersuite])
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[params.version])
        .unwrap()
        .with_root_certificates(root_store);

    let mut cfg = if clientauth == ClientAuth::Yes {
        cfg.with_client_auth_cert(
            params.key_type.get_client_chain(),
            params.key_type.get_client_key(),
        )
            .unwrap()
    } else {
        cfg.with_no_client_auth()
    };

    if resume != ResumptionParam::No {
        cfg.resumption = Resumption::in_memory_sessions(128);
    } else {
        cfg.resumption = Resumption::disabled();
    }

    cfg
}

fn bench_handshake(params: &BenchmarkParam, clientauth: ClientAuth, resume: ResumptionParam) {
    let client_config = Arc::new(make_client_config(params, clientauth, resume));
    let server_config = Arc::new(make_server_config(params, clientauth, resume, None));

    assert!(params.ciphersuite.version() == params.version);

    let server_name = "localhost".try_into().unwrap();
    let mut client = ClientConnection::new(Arc::clone(&client_config), server_name).unwrap();
    let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();

    transfer(&mut client, &mut server, None);
    transfer(&mut server, &mut client, None);
    transfer(&mut client, &mut server, None);
    transfer(&mut server, &mut client, None);
}

fn do_handshake_step(client: &mut ClientConnection, server: &mut ServerConnection) -> bool {
    if server.is_handshaking() || client.is_handshaking() {
        transfer(client, server, None);
        transfer(server, client, None);
        true
    } else {
        false
    }
}

fn do_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    while do_handshake_step(client, server) {}
}

fn bench_bulk(params: &BenchmarkParam, plaintext_size: u64, max_fragment_size: Option<usize>) {
    let client_config = Arc::new(make_client_config(
        params,
        ClientAuth::No,
        ResumptionParam::No,
    ));
    let server_config = Arc::new(make_server_config(
        params,
        ClientAuth::No,
        ResumptionParam::No,
        max_fragment_size,
    ));

    let server_name = "localhost".try_into().unwrap();
    let mut client = ClientConnection::new(client_config, server_name).unwrap();
    client.set_buffer_limit(None);
    let mut server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    server.set_buffer_limit(None);

    do_handshake(&mut client, &mut server);

    let mut buf = Vec::new();
    buf.resize(plaintext_size as usize, 0u8);

    server.writer().write_all(&buf).unwrap();
    transfer(&mut server, &mut client, Some(buf.len()));
}

// fn main() {
//     for test in ALL_BENCHMARKS.iter() {
//         bench_bulk(test, 1024 * 1024, None);
//         bench_bulk(test, 1024 * 1024, Some(10000));
//         bench_handshake(test, ClientAuth::No, ResumptionParam::No);
//         bench_handshake(test, ClientAuth::Yes, ResumptionParam::No);
//         bench_handshake(test, ClientAuth::No, ResumptionParam::SessionID);
//         bench_handshake(test, ClientAuth::Yes, ResumptionParam::SessionID);
//         bench_handshake(test, ClientAuth::No, ResumptionParam::Tickets);
//         bench_handshake(test, ClientAuth::Yes, ResumptionParam::Tickets);
//     }
// }

// criterion_group!(
//     name = benches;
//     config = Criterion::default().with_measurement(Perf::new(Builder::from_hardware_event(Hardware::Instructions)));
//     targets = run_benchmark
// );
//
// // criterion_group!(benches, run_benchmark);
// criterion_main!(benches);

fn handshake_no_resume() {
    let test = &black_box(BenchmarkParam::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        &rustls::version::TLS13,
    ));

    bench_handshake(test, black_box(ClientAuth::No), black_box(ResumptionParam::No));
}

fn handshake_session_id() {
    let test = &black_box(BenchmarkParam::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        &rustls::version::TLS13,
    ));

    bench_handshake(test, black_box(ClientAuth::No), black_box(ResumptionParam::SessionID));
}

fn handshake_ticket() {
    let test = &black_box(BenchmarkParam::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        &rustls::version::TLS13,
    ));

    bench_handshake(test, black_box(ClientAuth::No), black_box(ResumptionParam::Tickets));
}

fn bulk() {
    let test = &black_box(BenchmarkParam::new(
        KeyType::Rsa,
        rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
        &rustls::version::TLS13,
    ));

    bench_bulk(&test, black_box(1024 * 1024), black_box(None));
}

iai::main!(handshake_no_resume, handshake_session_id, handshake_ticket, bulk);
// iai::main!(handshake_no_resume);

// fn main() {
//     bench_bulk_with_max_fragment_size();
//     println!("Done!");
//
// }