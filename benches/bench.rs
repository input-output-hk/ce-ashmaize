use criterion::{Criterion, criterion_group, criterion_main};
use hashmaze::Rom;
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

fn criterion_benchmark(c: &mut Criterion) {
    const GB: usize = 1_024 * 1_024 * 1_024;

    c.bench_function("hashmaze/initialize", |b| {
        b.iter(|| Rom::new(b"password", 2 * GB))
    });

    let rom = Rom::new(b"password", 2 * GB);
    c.bench_function("hashmaze/hash", |b| {
        b.iter(|| hashmaze::hash(b"salt", &rom, 256))
    });

    c.bench_function("RandomX/initialize", |b| {
        b.iter(|| {
            RandomXVM::new(
                RandomXFlag::FLAG_DEFAULT,
                Some(RandomXCache::new(RandomXFlag::FLAG_DEFAULT, b"key").unwrap()),
                None,
            )
        })
    });

    let vm = RandomXVM::new(
        RandomXFlag::FLAG_DEFAULT,
        Some(RandomXCache::new(RandomXFlag::FLAG_DEFAULT, b"key").unwrap()),
        None,
    )
    .unwrap();
    c.bench_function("RandomX/hash", |b| b.iter(|| vm.calculate_hash(b"data")));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
