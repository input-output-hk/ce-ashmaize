use ashmaize::{Rom, RomGenerationType};
use criterion::{Criterion, criterion_group, criterion_main};
use randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

fn criterion_benchmark(c: &mut Criterion) {
    const GB: usize = 1_024 * 1_024 * 1_024;
    const MB: usize = 1_024 * 1_024;

    // ashmaize/initialize is taking a long time, so set the sample size to the minimum
    let mut group = c.benchmark_group("ashmaize");
    group.sample_size(10);
    group.bench_function("initialize", |b| {
        b.iter(|| {
            Rom::new(
                b"password",
                RomGenerationType::TwoStep {
                    pre_size: 16 * MB,
                    mixing_numbers: 4,
                },
                2 * GB,
            )
        })
    });
    group.finish();

    let rom = Rom::new(
        b"password",
        RomGenerationType::TwoStep {
            pre_size: 16 * MB,
            mixing_numbers: 4,
        },
        2 * GB,
    );
    c.bench_function("ashmaize/hash-1", |b| {
        b.iter(|| ashmaize::hash(b"salt", &rom, 8, 256))
    });
    c.bench_function("ashmaize/hash-2", |b| {
        b.iter(|| ashmaize::hash(b"salt2", &rom, 8, 256))
    });
    c.bench_function("ashmaize/hash-3", |b| {
        b.iter(|| ashmaize::hash(b"salt3", &rom, 8, 256))
    });
    c.bench_function("ashmaize/hash-4", |b| {
        b.iter(|| ashmaize::hash(b"salt4", &rom, 8, 256))
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
