use crate::components::{footer::Footer, header::Header};
use leptos::prelude::*;

#[component]
pub fn Main(children: Children) -> impl IntoView {
    view! {
        <main>

        <div class="bg-gradient-to-br from-gray-900 via-gray-800 to-black text-white min-h-screen">
            <Header />

            {children()}

            <Footer />
        </div>
        </main>
    }
}
