use std::time::Duration;

use ashmaize::{Rom, RomGenerationType, hash};
use leptos::{prelude::*, task::spawn_local};

fn leading_zeros(digest: &[u8; 64], expected: u32) -> bool {
    let mut count = 0;

    for byte in digest {
        let leading_zeros = byte.leading_zeros();
        count += leading_zeros;
        if leading_zeros != 8 {
            break;
        }
    }

    count == expected
}

#[component]
pub fn Ashmaize() -> impl IntoView {
    let (rom_size, set_rom_size) = signal(1_024);
    let (nb_instrs, set_nb_instrs) = signal(256u32);
    let (nb_loops, _set_nb_loops) = signal(8u32);
    let (difficulty, set_difficulty) = signal(4u32);
    let (is_mining, set_is_mining) = signal(false);
    let (result, set_result) = signal(None::<(u64, u64, std::time::Duration)>);
    let (status, set_status) = signal(String::new());

    let start_mining = move || {
        if is_mining.get() {
            return;
        }

        set_is_mining.set(true);
        set_result.set(None);
        set_status.set("Initializing ROM...".to_string());

        spawn_local(async move {
            let rom = Rom::new(&[], RomGenerationType::FullRandom, rom_size.get());
            let target_zeros = difficulty.get();
            let mut salt = 0u64;
            let mut hash_count = 0u64;
            // let start_time = std::time::Instant::now();

            set_status.set("Mining...".to_string());

            loop {
                let hash_result = hash(&salt.to_be_bytes(), &rom, nb_loops.get(), nb_instrs.get());
                hash_count += 1;

                // Check if hash has the required number of leading zeros
                if leading_zeros(&hash_result, target_zeros) {
                    let elapsed = Duration::ZERO;
                    // let elapsed = start_time.elapsed();
                    set_result.set(Some((salt, hash_count, elapsed)));
                    set_status.set(format!("Found salt: {}", salt));
                    break;
                }

                salt += 1;

                // Update status periodically
                if hash_count % 10000 == 0 {
                    set_status.set(format!("Tried {} hashes...", hash_count));
                }
            }

            set_is_mining.set(false);
        });
    };
    view! {
        <div class="max-w-4xl mx-auto p-6 bg-gray-900 rounded-lg shadow-lg">
            <h1 class="text-3xl font-bold mb-8 text-center text-gray-100">"Ashmaize Interactive Demo"</h1>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div class="space-y-6">
                    <h2 class="text-xl font-semibold text-gray-200">"Configuration"</h2>

                    <div class="space-y-4">
                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-2">"ROM Size"</label>
                            <select
                                class="w-full p-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                on:change=move |ev| {
                                    let value = event_target_value(&ev);
                                    let rom_type = match value.as_str() {
                                        "1KB" => 1_024,
                                        "1MB" => 1_024 * 1_024,
                                        "1GB" => 1_024 * 1_024 * 1_024,
                                        _ => 1_024,
                                    };
                                    set_rom_size.set(rom_type);
                                }
                            >
                                <option value="1KB">"1KB"</option>
                                <option value="1MB">"1MB"</option>
                                <option value="1GB">"1GB"</option>
                            </select>
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-2">"Hash Parameter"</label>
                            <input
                                type="number"
                                class="w-full p-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                value=move || nb_instrs.get().to_string()
                                on:input=move |ev| {
                                    if let Ok(val) = event_target_value(&ev).parse::<u32>() {
                                        set_nb_instrs.set(val);
                                    }
                                }
                            />
                        </div>

                        <div>
                            <label class="block text-sm font-medium text-gray-300 mb-2">"Difficulty (Leading Zeros)"</label>
                            <input
                                type="number"
                                min="1"
                                max="32"
                                class="w-full p-2 border border-gray-600 bg-gray-800 text-gray-100 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                value=move || difficulty.get().to_string()
                                on:input=move |ev| {
                                    if let Ok(val) = event_target_value(&ev).parse::<u32>() {
                                        if val >= 1 && val <= 32 {
                                            set_difficulty.set(val);
                                        }
                                    }
                                }
                            />
                        </div>

                        <button
                            class="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 text-white font-medium py-2 px-4 rounded-md transition-colors"
                            disabled=move || is_mining.get()
                            on:click=move |_| start_mining()
                        >
                            {move || if is_mining.get() { "Mining..." } else { "Start Mining" }}
                        </button>
                    </div>
                </div>

                <div class="space-y-6">
                    <h2 class="text-xl font-semibold text-gray-200">"Results"</h2>

                    <div class="bg-gray-800 p-4 rounded-md">
                        <div class="mb-4">
                            <span class="text-sm font-medium text-gray-300">"Status: "</span>
                            <span class="text-sm text-gray-100">{move || status.get()}</span>
                        </div>

                        {move || match result.get() {
                            Some((salt, hash_count, duration)) => view! {
                                <div class="space-y-2">
                                    <div class="flex justify-between">
                                        <span class="text-sm font-medium text-gray-300">"Salt Found:"</span>
                                        <span class="text-sm text-gray-100 font-mono">{salt}</span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-sm font-medium text-gray-300">"Hashes Computed:"</span>
                                        <span class="text-sm text-gray-100">{hash_count.to_string()}</span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-sm font-medium text-gray-300">"Time Elapsed:"</span>
                                        <span class="text-sm text-gray-100">{format!("{:.2?}", duration)}</span>
                                    </div>
                                    <div class="flex justify-between">
                                        <span class="text-sm font-medium text-gray-300">"Hash Rate:"</span>
                                        <span class="text-sm text-gray-100">
                                            {format!("{:.0} H/s", hash_count as f64 / duration.as_secs_f64())}
                                        </span>
                                    </div>
                                </div>
                            }.into_any(),
                            None => view! {
                                <div class="text-sm text-gray-400">"No results yet. Configure parameters and start mining!"</div>
                            }.into_any()
                        }}
                    </div>
                </div>
            </div>

            <div class="mt-8 p-4 bg-gray-800 rounded-md">
                <h3 class="text-lg font-medium text-gray-100 mb-2">"How it works"</h3>
                <p class="text-sm text-gray-300">
                    "The Ashmaize algorithm generates a ROM based on the selected size, then searches for a salt value that, when hashed with the specified parameters, produces a hash with the required number of leading zeros (difficulty). Higher difficulty means more leading zeros required, making it exponentially harder to find a valid salt."
                </p>
            </div>
        </div>
    }
}
