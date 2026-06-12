use web_sys::{
    js_sys,
    wasm_bindgen::{JsCast, JsValue},
    HtmlAnchorElement,
};

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
