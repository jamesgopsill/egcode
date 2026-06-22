use leptos::prelude::*;
use leptos_router::{
    components::{Outlet, ParentRoute, Route, Router, Routes},
    path,
};
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

mod decrypt;
mod encrypt;
mod index;
mod navbar;
mod utils;

use decrypt::Decrypt;
use encrypt::Encrypt;
use index::Index;
use navbar::NavBar;

fn main() {
    console_error_panic_hook::set_once();
    mount_to_body(|| view! { <App /> });
}

#[component]
fn App() -> impl IntoView {
    // Create a new device private-public key pair for demonstration
    // purposes.
    let device_private_key = StaticSecret::random_from_rng(OsRng);
    let device_public_key = PublicKey::from(&device_private_key);
    let device_private_key = RwSignal::<StaticSecret>::new(device_private_key);
    let device_public_key = RwSignal::<PublicKey>::new(device_public_key);
    view! {
        <Router base="/egcode">
            <Routes fallback=NotFound>
                <ParentRoute path=path!("/") view=MainLayout>
                    <Route path=path!("") view=Index />
                    <Route
                        path=path!("/decrypt")
                        view=move || {
                            view! {
                                <Decrypt
                                    device_public_key=device_public_key
                                    device_private_key=device_private_key
                                />
                            }
                        }
                    />
                    <Route path=path!("/encrypt") view=Encrypt />
                </ParentRoute>
            </Routes>
        </Router>
    }
}

#[component]
fn MainLayout() -> impl IntoView {
    view! {
        <NavBar />
        <div class="container-fluid">
            <Outlet />
        </div>
        <Footer />
    }
}

#[component]
fn NotFound() -> impl IntoView {
    view! {
        <div>
            <h1>"404 - Page Not Found"</h1>
            <p>"The page you are looking for does not exist."</p>
        </div>
    }
}

#[component]
fn Footer() -> impl IntoView {
    view! {
        <footer>
            <hr />
            <p class="text-center text-muted">
                {"Made in Rust with "}<i class="bi bi-heart-fill text-danger"></i>{" and "}
                <i class="bu bi-cup-hot-fill"></i>{"."}
            </p>
            <p class="text-center text-muted">{"James Gopsill - 2026"}</p>
        </footer>
    }
}
