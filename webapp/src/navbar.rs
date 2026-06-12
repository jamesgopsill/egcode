use leptos::prelude::*;

#[component]
pub fn NavBar() -> impl IntoView {
    view! {
        <nav class="navbar navbar-expand-lg bg-body-tertiary">
            <div class="container-fluid">
                <a class="navbar-brand" href="./">
                    Encrypt GCode Demonstrator
                </a>
                <button
                    class="navbar-toggler"
                    type="button"
                    data-bs-toggle="collapse"
                    data-bs-target="#navbarNav"
                    aria-controls="navbarNav"
                    aria-expanded="false"
                    aria-label="Toggle navigation"
                >
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav">
                        <li class="nav-item">
                            <a class="nav-link" href="./">
                                About
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="./decrypt">
                                Decrypt
                            </a>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link" href="./encrypt">
                                Encrypt
                            </a>
                        </li>
                    </ul>
                </div>
            </div>
        </nav>
    }
}
