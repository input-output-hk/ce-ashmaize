use crate::components::main::Main;
use leptos::prelude::*;

/// 404 Not Found Page
#[component]
pub fn NotFound() -> impl IntoView {
    view! {
        <Main>
            // Hero Section
            <section class="container mx-auto px-6 py-20 text-center">
                <div class="max-w-4xl mx-auto">
                    <h2 class="text-6xl font-bold mb-6 bg-gradient-to-r from-gray-200 to-gray-400 bg-clip-text text-transparent">
                        "Uh oh!"
                    </h2>
                    <p class="text-xl text-gray-400 mb-8 leading-relaxed">
                        "The page you are looking for couldn't be found."
                    </p>
                </div>
            </section>

            <section class="container mx-auto px-6 py-20 text-center">
                <div class="max-w-4xl mx-auto">
                    <h2 class="text-6xl font-bold mb-6 bg-gradient-to-r from-gray-200 to-gray-400 bg-clip-text text-transparent">
                        "So what's next?"
                    </h2>
                    <p class="text-xl text-gray-400 mb-8 leading-relaxed">
                        "Now that you are here, why not checkout the main page?"
                    </p>
                    <div class="flex flex-col sm:flex-row gap-4 justify-center">
                        <a href="/"
                           class="border border-gray-500 text-gray-300 hover:bg-gray-700 hover:text-white px-8 py-3 rounded-lg font-semibold transition-colors">
                            "Main page"
                        </a>
                    </div>
                </div>
            </section>
        </Main>
    }
}
