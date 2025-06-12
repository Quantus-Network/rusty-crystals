use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rusty_crystals_dilithium::ml_dsa_87::Keypair;

fn benchmark_keypair_generation(c: &mut Criterion) {
    c.bench_function("keypair generation", |b| {
        b.iter(|| Keypair::generate(black_box(None)))
    });
}

criterion_group!(benches, benchmark_keypair_generation);
criterion_main!(benches);
