use egcode::decrypt::Decrypt;
use leptos::{prelude::*, reactive::spawn_local};
use web_sys::{
    Event, HtmlInputElement, MouseEvent,
    js_sys::{self, futures::JsFuture},
    wasm_bindgen::JsCast,
};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::download::download_gcode;

#[component]
pub fn Decrypt(
    device_private_key: RwSignal<StaticSecret>,
    device_public_key: RwSignal<PublicKey>,
) -> impl IntoView {
    // Should only need to be tracked on mount.
    let device_public_key_hex =
        RwSignal::<String>::new(hex::encode(device_public_key.get_untracked()));
    // let port = RwSignal::<Option<SerialPort>>::default();
    // let connected = move || port.get().is_some();
    let err_msg = RwSignal::<Option<&str>>::default();
    let suc_msg = RwSignal::<Option<&str>>::default();
    // let ok = RwSignal::<bool>::new(false);
    let encrypted_gcode = RwSignal::<Vec<u8>>::default();
    let password = RwSignal::<String>::default();
    let selected = RwSignal::<String>::new("3".to_string());
    let fname = RwSignal::<String>::default();

    /*
    let connect = move |_: MouseEvent| {
        spawn_local(async move {
            let window = window();
            let serial = window.navigator().serial();

            let Ok(p) = JsFuture::from(serial.request_port()).await else {
                err_msg.set(Some("Connection cancelled by user."));
                return;
            };
            port.set(Some(p));

            let options = SerialOptions::new(115_200);
            let p = port.get().unwrap();

            if JsFuture::from(p.open(&options)).await.is_err() {
                err_msg.set(Some("Failed to open port."));
                return;
            }

            let readable = p.readable();
            let Ok(reader): Result<ReadableStreamDefaultReader, _> =
                readable.get_reader().dyn_into()
            else {
                err_msg.set(Some("Could not create readable stream."));
                return;
            };

            let mut log: String = String::new();
            loop {
                let read_promise = reader.read();
                match JsFuture::from(read_promise).await {
                    Ok(r) => {
                        // Result is a JS object: { value: Uint8Array, done: bool }
                        let done = js_sys::Reflect::get(&r, &"done".into())
                            .unwrap()
                            .as_bool()
                            .unwrap_or(true);

                        if done {
                            break;
                        }

                        let chunk =
                            js_sys::Reflect::get(&r, &"value".into()).unwrap();
                        let uint8_array = js_sys::Uint8Array::new(&chunk);
                        let bytes = uint8_array.to_vec();

                        if let Ok(text) = String::from_utf8(bytes) {
                            log.push_str(&text);
                            let lines: Vec<&str> = log.lines().collect();
                            // Ignore the last line as is may be incomplete.
                            for line in &lines[..lines.len() - 1] {
                                console_log(line);
                                // TODO: if an ok signal then flag to send data.
                            }
                            match lines.last() {
                                Some(l) => log = l.to_string(),
                                None => log.clear(),
                            }
                        }
                    }
                    Err(_) => {
                        err_msg.set(Some("Read error."));
                        return;
                    }
                }
            }
        });
    };
    */

    let load_data = move |e: Event| {
        let target = event_target::<HtmlInputElement>(&e);
        let Some(files) = target.files() else {
            return;
        };
        let Some(f) = files.get(0) else { return };
        if !f.name().ends_with(".egcode") {
            err_msg.set(Some("Wrong file extension. Expected '.egcode'."));
            return;
        }
        let name = f.name().split(".egcode").next().unwrap().to_string();
        let name = format!("{name}.gcode");
        fname.set(name);
        spawn_local(async move {
            let promise = f.array_buffer();
            let result = JsFuture::from(promise).await;
            if let Ok(array_buffer_js) = result {
                let array_buffer: js_sys::ArrayBuffer =
                    array_buffer_js.unchecked_into();
                encrypted_gcode
                    .set(js_sys::Uint8Array::new(&array_buffer).to_vec())
            }
        });
    };

    let decrypt_and_download = move |_: MouseEvent| {
        let enc = encrypted_gcode.get_untracked();
        let mut decryptor = Decrypt::new(enc.as_slice());
        match selected.get().as_str() {
            "1" => {
                let pwd = password.get_untracked();
                if decryptor.with_password(pwd.as_bytes()).is_err() {
                    err_msg.set(Some("Decryption error."));
                };
            }
            "2" => {
                let key = device_private_key.get_untracked();
                if decryptor.with_device_key(*key.as_bytes()).is_err() {
                    err_msg.set(Some("Decryption error."));
                }
            }
            "3" => {
                let pwd = password.get_untracked();
                let key = device_private_key.get_untracked();
                if decryptor
                    .with_password_and_device_key(
                        pwd.as_bytes(),
                        *key.as_bytes(),
                    )
                    .is_err()
                {
                    err_msg.set(Some("Decryption error."));
                }
            }
            _ => {}
        }

        let mut line: Vec<u8> = Vec::new();
        let mut gcode: Vec<u8> = Vec::new();

        loop {
            match decryptor.next(&mut line) {
                Ok(Some(n)) => {
                    gcode.extend_from_slice(&line[..n]);
                    line.clear();
                }
                Ok(None) => {
                    std::println!("EOF");
                    break;
                }
                Err(e) => {
                    std::println!("[Error] {e:?}");
                    panic!("Errored");
                }
            }
        }

        let fname = fname.get_untracked();

        match download_gcode(gcode, fname.as_str()) {
            Ok(()) => suc_msg.set(Some("Horray! You've decrypted some gcode.")),
            Err(e) => {
                err_msg.set(Some(e));
            }
        }
    };

    view! {
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
        <div class="row mt-5 justify-content-center">
            <div class="col-sm-10 col-md-8">
                <div class="card">
                    <div class="card-header">
                        {"This Devices Public Key (A new one is created each time the page is refreshed)."}
                    </div>
                    <div class="card-body">
                        <input class="form-control" bind:value=device_public_key_hex disabled />
                    </div>
                </div>
                <div class="card mt-3 mb-5">
                    <div class="card-header">{"Decrypt Gcode (Locally in the browser)"}</div>
                    <div class="card-body">
                        <div class="form-floating">
                            <select bind:value=selected class="form-control mb-3">
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
                            accept=".egcode"
                            on:change=load_data
                        />
                        <Show when=move || selected.get() != "2">
                            <div class="form-floating">
                                <input
                                    class="form-control mb-3"
                                    type="password"
                                    bind:value=password
                                />
                                <label for="floatingSelect">{"Password"}</label>
                            </div>
                        </Show>
                        <button
                            class="btn btn-outline-primary mt-1 me-3"
                            on:click=decrypt_and_download
                        >
                            {"Decrypt and Download"}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    }
}

/*
<div class="col-6">
    <div class="card">
        <div class="card-header">{"Connect a Device (3D Printer via USB)"}</div>
        <div class="card-body">
            <Show when=move || !connected()>
                <button class="btn btn-outline-primary" on:click=connect>
                    {"Connect"}
                </button>
            </Show>
            <Show when=connected>
                <button class="btn btn-outline-danger">{"Disconnect"}</button>
            </Show>
        </div>
    </div>
</div>
    <button class="btn btn-outline-primary" disabled=move || !connected()>
        {"Decrypt and Print"}
    </button>
*/
