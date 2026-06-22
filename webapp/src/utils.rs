use std::{
    pin::pin,
    task::{Context, Poll, Waker},
};

use gloo_timers::future::TimeoutFuture;
use web_sys::{
    HtmlAnchorElement, js_sys,
    wasm_bindgen::{JsCast, JsValue},
};

const MAX_ITER: u32 = 10_000;

pub async fn poll_fut<T, E>(
    fut: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let mut pinned_fut = pin!(fut);
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
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
                return result;
            }
        }
    }
}

pub fn download_gcode(
    data: Vec<u8>,
    filename: &str,
) -> Result<(), &'static str> {
    // Creating the download
    let blob_parts = js_sys::Array::new();
    blob_parts.push(&JsValue::from(data));

    let blob_properties = web_sys::BlobPropertyBag::new();
    blob_properties.set_type("application/octet-stream");

    let Ok(blob) = web_sys::Blob::new_with_str_sequence_and_options(
        &blob_parts,
        &blob_properties,
    ) else {
        return Err("Failed to create blob.");
    };

    let Ok(url) = web_sys::Url::create_object_url_with_blob(&blob) else {
        return Err("Failed to create download url.");
    };

    // Create a hidden <a> element to trigger the download
    let document = web_sys::window().unwrap().document().unwrap();
    let link: HtmlAnchorElement =
        document.create_element("a").unwrap().unchecked_into();
    link.set_href(&url);
    link.set_download(filename);

    // Programmatically click the link
    document.body().unwrap().append_child(&link).unwrap();
    link.click();

    // Cleanup
    document.body().unwrap().remove_child(&link).unwrap();
    web_sys::Url::revoke_object_url(&url).expect("Failed to revoke URL");
    Ok(())
}
