use leptos::prelude::*;

/// Default Footer
#[component]
pub fn Footer() -> impl IntoView {
    view! {
        // add a component that will be at the bottom of the page
        // so that the footer that is always at a fixed size doesn't
        // hide other components.
        <div class="h-16"></div>

        <footer class="fixed bottom-0 left-0 right-0 bg-gray-900 bg-opacity-80 backdrop-blur-sm border-t border-gray-700 z-10">
            <div class="container mx-auto px-6 py-8 text-center">
                <p class="text-gray-500">"Built with ❤️ using Leptos and TailwindCSS"</p>
            </div>
        </footer>
    }
}
