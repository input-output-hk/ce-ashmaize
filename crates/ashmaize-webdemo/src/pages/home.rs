use crate::components::{ashmaize::Ashmaize, main::Main};
use leptos::prelude::*;

/// Default Home Page
#[component]
pub fn Home() -> impl IntoView {
    view! {
        <Main>

            // Hero Section
            <section class="container mx-auto px-6 py-20 text-center">
                <div class="max-w-4xl mx-auto">
                    <h2 class="text-6xl font-bold mb-6 bg-gradient-to-r from-gray-200 to-gray-400 bg-clip-text text-transparent">
                        "Welcome to Ashmaize"
                    </h2>
                    <p class="text-xl text-gray-400 mb-8 leading-relaxed">
                        "ASIC Resistant PoW Algorithm for scavenger mining"
                    </p>
                    <div class="flex flex-col sm:flex-row gap-4 justify-center">
                        <button class="bg-gray-700 hover:bg-gray-600 text-white px-8 py-3 rounded-lg font-semibold transition-colors shadow-lg">
                            "Get Started"
                        </button>
                        <a href="http://github.com/input-output-hk/ce-ashmaize"
                           class="border border-gray-500 text-gray-300 hover:bg-gray-700 hover:text-white px-8 py-3 rounded-lg font-semibold transition-colors"
                           target="_blank">
                            "View on GitHub"
                        </a>
                    </div>
                </div>
            </section>

            // Features Section
            <section id="features" class="container mx-auto px-6 py-20">
                <h3 class="text-4xl font-bold text-center mb-16">"Key Features"</h3>
                <div class="grid md:grid-cols-3 gap-8">
                    <div class="bg-gray-800 bg-opacity-80 backdrop-blur-sm rounded-xl p-8 border border-gray-700">
                        <div class="text-gray-400 text-3xl mb-4">"🪶"</div>
                        <h4 class="text-xl font-semibold mb-4">"Lightweight"</h4>
                        <p class="text-gray-400">"The code to run the ashmaize algorithm is lightweight and can be embedded in any system."</p>
                    </div>
                    <div class="bg-gray-800 bg-opacity-80 backdrop-blur-sm rounded-xl p-8 border border-gray-700">
                        <div class="text-gray-400 text-3xl mb-4">"🎨"</div>
                        <h4 class="text-xl font-semibold mb-4">"Beautiful Design"</h4>
                        <p class="text-gray-400">"Crafted with care by expert cryptographic engineers."</p>
                    </div>
                    <div class="bg-gray-800 bg-opacity-80 backdrop-blur-sm rounded-xl p-8 border border-gray-700">
                        <div class="text-gray-400 text-3xl mb-4">"🔧"</div>
                        <h4 class="text-xl font-semibold mb-4">"ASIC Resistant"</h4>
                        <p class="text-gray-400">"Implement strong ASIC resistant mechanism to protect your mining work from unfair hardware optimisations."</p>
                    </div>
                </div>
            </section>

            // Demo Section
            <section id="demo" class="container mx-auto px-6 py-20">
                <h3 class="text-4xl font-bold text-center mb-16">"Interactive Demo"</h3>
                <div class="max-w-2xl mx-auto bg-gray-800 bg-opacity-80 backdrop-blur-sm rounded-xl p-8 border border-gray-700">
                    <Ashmaize />
                </div>
            </section>

        </Main>
    }
}
