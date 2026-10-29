//! Throughput benchmarks for the AEAD primitives and the chunked stream format.
//!
//! `raw/*` measures the bare chacha20poly1305 crate in place, so the gap to
//! `stream/*` is the framing overhead (copies, allocations, nonce generation).

use std::time::Duration;

use axiomvault_crypto::aead::{decrypt, encrypt};
use axiomvault_crypto::keys::KEY_LENGTH;
use axiomvault_crypto::stream::{DecryptingStream, EncryptingStream, DEFAULT_CHUNK_SIZE};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};

const KEY: [u8; KEY_LENGTH] = [42u8; KEY_LENGTH];
const STREAM_LEN: usize = 64 * 1024 * 1024;

fn bench_aead(c: &mut Criterion) {
    let plaintext = vec![0xA5u8; DEFAULT_CHUNK_SIZE];
    let ciphertext = encrypt(&KEY, &plaintext).unwrap();
    let mut group = c.benchmark_group("aead_64KiB");
    group.throughput(Throughput::Bytes(DEFAULT_CHUNK_SIZE as u64));

    let cipher = XChaCha20Poly1305::new(&KEY.into());
    let nonce = XNonce::default();
    let mut buffer = plaintext.clone();
    group.bench_function("raw_encrypt_in_place", |b| {
        b.iter(|| {
            cipher
                .encrypt_in_place_detached(&nonce, b"", black_box(&mut buffer))
                .unwrap()
        })
    });
    group.bench_function("encrypt", |b| {
        b.iter(|| encrypt(&KEY, black_box(&plaintext)).unwrap())
    });
    group.bench_function("decrypt", |b| {
        b.iter(|| decrypt(&KEY, black_box(&ciphertext)).unwrap())
    });
    group.finish();
}

fn bench_stream(c: &mut Criterion) {
    let plaintext = vec![0xA5u8; STREAM_LEN];
    let encrypting = EncryptingStream::new(&KEY).unwrap();
    let decrypting = DecryptingStream::new(&KEY).unwrap();
    let mut ciphertext = Vec::with_capacity(encrypting.encrypted_len(STREAM_LEN as u64) as usize);
    encrypting
        .encrypt_stream(&plaintext[..], &mut ciphertext)
        .unwrap();
    let mut output = Vec::with_capacity(STREAM_LEN);

    let mut group = c.benchmark_group("stream_64MiB");
    group.throughput(Throughput::Bytes(STREAM_LEN as u64));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));
    group.bench_function("encrypt", |b| {
        b.iter(|| {
            output.clear();
            encrypting
                .encrypt_stream(black_box(&plaintext[..]), &mut output)
                .unwrap()
        })
    });
    group.bench_function("decrypt", |b| {
        b.iter(|| {
            output.clear();
            decrypting
                .decrypt_stream(black_box(&ciphertext[..]), &mut output)
                .unwrap()
        })
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = bench_aead, bench_stream
}
criterion_main!(benches);
