use crate::bench_lib::{black_box, Benchmark};
use std::fs;
use std::io::{self, Read, Write};
use std::ops::Deref;
use std::ops::DerefMut;
use std::sync::Arc;

use rustls::client::Resumption;
use rustls::crypto::ring::Ring;
use rustls::server::{NoServerSessionStorage, ServerSessionMemoryCache, WebPkiClientVerifier};
use rustls::RootCertStore;
use rustls::Ticketer;
use rustls::{ClientConfig, ClientConnection};
use rustls::{ConnectionCommon, SideData};
use rustls::{ServerConfig, ServerConnection};

mod bench_lib;

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
            let written = left.write_tls(&mut tls_buf[sz..].as_mut()).unwrap();
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
            Self::No => "no_resume",
            Self::SessionID => "session_id",
            Self::Tickets => "tickets",
        }
    }
}

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
            WebPkiClientVerifier::builder(Arc::new(client_auth_roots))
                .build()
                .unwrap()
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

fn new_connection(
    params: &BenchmarkParam,
    clientauth: ClientAuth,
    resume: ResumptionParam,
) -> (ClientConnection, ServerConnection) {
    let client_config = Arc::new(make_client_config(params, clientauth, resume));
    let server_config = Arc::new(make_server_config(params, clientauth, resume, None));

    assert!(params.ciphersuite.version() == params.version);

    let server_name = "localhost".try_into().unwrap();
    let client = ClientConnection::new(Arc::clone(&client_config), server_name).unwrap();
    let server = ServerConnection::new(Arc::clone(&server_config)).unwrap();
    (client, server)
}

fn bench_new_connection(params: &BenchmarkParam, clientauth: ClientAuth, resume: ResumptionParam) {
    black_box(new_connection(params, clientauth, resume));
}

fn bench_handshake(params: &BenchmarkParam, clientauth: ClientAuth, resume: ResumptionParam) {
    let (mut client, mut server) = new_connection(params, clientauth, resume);

    transfer(&mut client, &mut server, None);
    transfer(&mut server, &mut client, None);
    transfer(&mut client, &mut server, None);
    transfer(&mut server, &mut client, None);
}

fn do_handshake(client: &mut ClientConnection, server: &mut ServerConnection) {
    loop {
        transfer(client, server, None);
        transfer(server, client, None);
        if !server.is_handshaking() && !client.is_handshaking() {
            break;
        }
    }
}

fn bench_transfer(params: &BenchmarkParam, plaintext_size: u64, max_fragment_size: Option<usize>) {
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

fn add_benchmarks_for_params(benchmarks: &mut Vec<Benchmark>, get_param: fn() -> BenchmarkParam) {
    let tls = format!("{:?}", get_param().version);
    let all_resumption_params = [
        ResumptionParam::No,
        ResumptionParam::SessionID,
        ResumptionParam::Tickets,
    ];

    // Benchmark handshake with and without resumption
    for resumption_param in all_resumption_params {
        benchmarks.extend([
            Benchmark::new(
                format!("new_conn_{}_{tls}", resumption_param.label()),
                move || {
                    bench_new_connection(
                        &black_box(get_param()),
                        black_box(ClientAuth::No),
                        black_box(ResumptionParam::No),
                    )
                },
            )
            .hidden(),
            Benchmark::new(
                format!("handshake_{}_{tls}", resumption_param.label()),
                move || {
                    bench_handshake(
                        &black_box(get_param()),
                        black_box(ClientAuth::No),
                        black_box(ResumptionParam::No),
                    )
                },
            )
            .exclude_setup_instructions(format!("new_conn_{}_{tls}", resumption_param.label())),
        ])
    }

    // Benchmark data transfer
    benchmarks.extend([
        Benchmark::new(format!("transfer_no_resume_{tls}"), move || {
            bench_transfer(
                &black_box(get_param()),
                black_box(1024 * 1024),
                black_box(None),
            )
        })
        .exclude_setup_instructions(format!("handshake_no_resume_{tls}")),
    ]);
}

fn main() {
    let params = [
        || {
            BenchmarkParam::new(
                KeyType::Rsa,
                rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                &rustls::version::TLS12,
            )
        },
        || {
            BenchmarkParam::new(
                KeyType::Rsa,
                rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
                &rustls::version::TLS13,
            )
        },
    ];

    let mut benchmarks = Vec::new();
    for param in params {
        add_benchmarks_for_params(&mut benchmarks, param);
    }

    bench_lib::main(&benchmarks);
}
