use leptos::prelude::*;

/// Default Home Page
#[component]
pub fn Header() -> impl IntoView {
    view! {
        <header class="bg-gray-900 bg-opacity-80 backdrop-blur-sm border-b border-gray-700">
            <div class="container mx-auto px-6 py-4 flex items-center justify-between">
                <h1 class="text-2xl font-bold text-white">"Ashmaize"</h1>
                <nav class="space-x-6">
                    <a href="#features" class="text-gray-300 hover:text-white transition-colors">"Features"</a>
                    <a href="#demo" class="text-gray-300 hover:text-white transition-colors">"Demo"</a>
                    <a href="http://github.com/input-output-hk/ce-ashmaize" target="_blank" class="text-gray-300 hover:text-white transition-colors">"Github"</a>
                </nav>
            </div>
        </header>
    }
}
