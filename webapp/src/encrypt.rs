use std::{
    pin::pin,
    task::{Context, Poll, Waker},
};

use egcode::encrypt::Encrypt;
use gloo_timers::future::TimeoutFuture;
use leptos::{prelude::*, reactive::spawn_local};
use rand_core::OsRng;
use web_sys::{Event, HtmlInputElement, MouseEvent, js_sys::futures::JsFuture};

use crate::download::download_gcode;

const ROUNDS: u32 = 600_000;

#[component]
pub fn Encrypt() -> impl IntoView {
    let device_public_key = RwSignal::<String>::default();
    let err_msg = RwSignal::<Option<&str>>::default();
    let suc_msg = RwSignal::<Option<&str>>::default();
    let gcode = RwSignal::<String>::default();
    let password = RwSignal::<String>::default();
    let confirm_password = RwSignal::<String>::default();
    let selected = RwSignal::<String>::new("3".to_string());
    let fname = RwSignal::<String>::default();
    let spinner = RwSignal::<bool>::new(false);

    let read_gcode = move |e: Event| {
        let target = event_target::<HtmlInputElement>(&e);
        let Some(files) = target.files() else {
            return;
        };
        let Some(f) = files.get(0) else { return };
        if !f.name().ends_with(".gcode") {
            err_msg.set(Some("Wrong file extension. Expected '.gcode'."));
            return;
        }
        let name = f.name().split(".gcode").next().unwrap().to_string();
        let name = format!("{name}.egcode");
        fname.set(name);
        spawn_local(async move {
            let promise = f.text();
            let result = JsFuture::from(promise).await;
            if let Ok(text) = result {
                gcode.set(text.as_string().unwrap_or_default());
            }
        });
    };

    let encrypt = move |_e: MouseEvent| {
        spawn_local(async move {
            spinner.set(true);
            let selected = selected.get_untracked();
            let gcode = gcode.get_untracked();
            let encryptor = Encrypt::new(gcode.as_bytes(), OsRng);
            let mut writer: Vec<u8> = Vec::new();

            match selected.as_str() {
                "1" => {
                    let password = password.get_untracked();
                    let confirm_password = confirm_password.get_untracked();
                    if password != confirm_password {
                        err_msg.set(Some("Passwords do not match."));
                        return;
                    }
                    let fut = encryptor.with_password(
                        &mut writer,
                        password.as_bytes(),
                        ROUNDS,
                    );
                    let mut pinned_fut = pin!(fut);
                    let waker = Waker::noop();
                    let mut cx = Context::from_waker(waker);
                    const MAX_ITER: u32 = 10_000;
                    let mut iter: u32 = 0;
                    loop {
                        match pinned_fut.as_mut().poll(&mut cx) {
                            Poll::Pending => {
                                iter += 1;
                                // Pause after so many iterations to enable the
                                // UI to stay responsive.
                                if iter >= MAX_ITER {
                                    TimeoutFuture::new(1).await;
                                    iter = 0;
                                }
                            }
                            Poll::Ready(result) => {
                                if result.is_err() {
                                    spinner.set(false);
                                    err_msg.set(Some("Encryption Error."));
                                    return;
                                }
                                break;
                            }
                        }
                    }
                }
                "2" => {
                    let machine_public_key = device_public_key.get_untracked();
                    let Ok(machine_public_key) =
                        hex::decode(machine_public_key)
                    else {
                        spinner.set(false);
                        err_msg.set(Some("Machine public key decode error."));
                        return;
                    };
                    let fut = encryptor
                        .with_device_key(&mut writer, &machine_public_key);
                    let mut pinned_fut = pin!(fut);
                    let waker = Waker::noop();
                    let mut cx = Context::from_waker(waker);
                    const MAX_ITER: u32 = 10_000;
                    let mut iter: u32 = 0;
                    loop {
                        match pinned_fut.as_mut().poll(&mut cx) {
                            Poll::Pending => {
                                iter += 1;
                                // Pause after so many iterations to enable the
                                // UI to stay responsive.
                                if iter >= MAX_ITER {
                                    TimeoutFuture::new(1).await;
                                    iter = 0;
                                }
                            }
                            Poll::Ready(result) => {
                                if result.is_err() {
                                    spinner.set(false);
                                    err_msg.set(Some("Encryption Error."));
                                    return;
                                }
                                break;
                            }
                        }
                    }
                }
                "3" => {
                    let password = password.get_untracked();
                    let confirm_password = confirm_password.get_untracked();
                    if password != confirm_password {
                        err_msg.set(Some("Passwords do not match."));
                        return;
                    }
                    let machine_public_key = device_public_key.get_untracked();
                    let Ok(machine_public_key) =
                        hex::decode(machine_public_key)
                    else {
                        spinner.set(false);
                        err_msg.set(Some("Machine public key decode error."));
                        return;
                    };
                    let fut = encryptor.with_password_and_device_key(
                        &mut writer,
                        password.as_bytes(),
                        ROUNDS,
                        &machine_public_key,
                    );
                    let mut pinned_fut = pin!(fut);
                    let waker = Waker::noop();
                    let mut cx = Context::from_waker(waker);
                    const MAX_ITER: u32 = 10_000;
                    let mut iter: u32 = 0;
                    loop {
                        match pinned_fut.as_mut().poll(&mut cx) {
                            Poll::Pending => {
                                iter += 1;
                                // Pause after so many iterations to enable the
                                // UI to stay responsive.
                                if iter >= MAX_ITER {
                                    TimeoutFuture::new(1).await;
                                    iter = 0;
                                }
                            }
                            Poll::Ready(result) => {
                                if result.is_err() {
                                    spinner.set(false);
                                    err_msg.set(Some("Encryption Error"));
                                    return;
                                }
                                break;
                            }
                        }
                    }
                }
                _ => {
                    err_msg.set(Some("Unknown encryption method."));
                    return;
                }
            };

            // Handle the fut

            let fname = fname.get_untracked();
            spinner.set(false);

            match download_gcode(writer, fname.as_str()) {
                Ok(()) => {
                    suc_msg.set(Some("Horray! You've protected your gcode and intellectual property!"));
                }
                Err(e) => {
                    err_msg.set(Some(e));
                }
            }
        });
    };

    view! {
        <div class="row justify-content-center">
            <div class="col-sm-10 col-md-8">
                <Show when=move || suc_msg.get().is_some()>
                    <div class="alert alert-success mt-3">
                        <strong>{"[SUCCESS] "}</strong>
                        {move || suc_msg.get()}
                    </div>
                </Show>
                <Show when=move || err_msg.get().is_some()>
                    <div class="alert alert-danger mt-3">
                        <strong>{"[ERROR] "}</strong>
                        {move || err_msg.get()}
                    </div>
                </Show>

                <div class="card mt-5 mb-5">
                    <div class="card-header">{"Encrypt Gcode (Locally in Browser)"}</div>
                    <div class="card-body">
                        <div class="form-floating">
                            <select bind:value=selected class="form-control mb-5">
                                <option value="1">{"Password"}</option>
                                <option value="2">{"Device Key"}</option>
                                <option value="3">{"Password and Device Key"}</option>
                            </select>
                            <label for="floatingSelect">{"Select Encryption Method"}</label>
                        </div>
                        <label class="form-label text-muted">
                            <small>{"GCode"}</small>
                        </label>
                        <input
                            class="form-control mb-3"
                            type="file"
                            accept=".gcode"
                            on:change=read_gcode
                        />
                        <Show when=move || selected.get() != "1">
                            <div class="form-floating">
                                <input
                                    class="form-control mb-3"
                                    type="text"
                                    bind:value=device_public_key
                                />
                                <label for="floatingSelect">
                                    {"Device Public Key (of the device you want to decrypt it on)"}
                                </label>
                            </div>
                        </Show>
                        <Show when=move || selected.get() != "2">
                            <div class="form-floating">
                                <input
                                    class="form-control mb-3"
                                    type="password"
                                    bind:value=password
                                />
                                <label for="floatingSelect">{"Password"}</label>
                            </div>
                            <div class="form-floating">
                                <input
                                    class="form-control mb-3"
                                    type="password"
                                    bind:value=confirm_password
                                />
                                <label for="floatingSelect">{"Confirm Password"}</label>
                            </div>
                        </Show>
                        <button
                            class="btn btn-outline-primary mt-2"
                            on:click=encrypt
                            disabled=spinner
                        >
                            <Show when=move || spinner.get()>
                                <div class="spinner-border spinner-border-sm" role="status">
                                    <span class="visually-hidden">Loading...</span>
                                </div>
                            </Show>
                            {" Encrypt"}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    }
}
