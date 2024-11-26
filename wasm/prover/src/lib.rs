pub(crate) mod hyper_io;
mod request_opt;
mod requests;

pub mod prover;
pub mod tdn_collector;
pub use prover::prover;

pub mod verify;
use tracing::error;
use tracing_subscriber::filter::FilterFn;
use tracing_subscriber::layer::Layer;
use tracing_subscriber::registry::LookupSpan;
pub use verify::verify;

use wasm_bindgen::prelude::*;

pub use crate::request_opt::{RequestOptions, VerifyResult};

pub use wasm_bindgen_rayon::init_thread_pool;

use js_sys::JSON;

use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, Response};

use std::panic;
use tracing::debug;
use tracing_subscriber::fmt::format::Pretty;
use tracing_subscriber::fmt::time::UtcTime;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;

use tracing_web::{performance_layer, MakeWebConsoleWriter};

extern crate console_error_panic_hook;

/// Log layer without prefixes.
struct PureLogLayer;

impl<S> Layer<S> for PureLogLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() == "pure_log" {
            let mut visitor = PureLogVisitor(String::new());
            event.record(&mut visitor);
            // Use console.log directly for pure logging
            web_sys::console::log_1(&visitor.0.into());
        }
    }
}

struct PureLogVisitor(String);

impl tracing::field::Visit for PureLogVisitor {
    fn record_debug(&mut self, _field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0 = format!("{:?}", value);
    }
}

#[wasm_bindgen]
pub fn setup_tracing_web(logging_filter: &str) {
    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_ansi(false) // Only partially supported across browsers
        .with_timer(UtcTime::rfc_3339()) // std::time is not available in browsers
        // .with_thread_ids(true)
        // .with_thread_names(true)
        .with_writer(MakeWebConsoleWriter::new()) // write events to the console
        .with_filter(FilterFn::new(|metadata: &tracing::Metadata<'_>| {
            metadata.target() != "pure_log"
        }));
    let perf_layer = performance_layer().with_details_from_fields(Pretty::default());

    let filter_layer = EnvFilter::builder()
        .parse(logging_filter)
        .unwrap_or_default();

    let pure_log_layer = PureLogLayer;

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .with(perf_layer)
        .with(pure_log_layer)
        .init(); // Install these as subscribers to tracing events

    // https://github.com/rustwasm/console_error_panic_hook
    panic::set_hook(Box::new(|info| {
        error!("panic occurred: {:?}", info);
        console_error_panic_hook::hook(info);
    }));

    debug!("🪵 Logging set up 🪵")
}

pub async fn fetch_as_json_string(url: &str, opts: &RequestInit) -> Result<String, JsValue> {
    let request = Request::new_with_str_and_init(url, opts)?;
    let window = web_sys::window().expect("Window object");
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;
    assert!(resp_value.is_instance_of::<Response>());
    let resp: Response = resp_value.dyn_into()?;
    let json = JsFuture::from(resp.json()?).await?;
    let stringified = JSON::stringify(&json)?;
    stringified
        .as_string()
        .ok_or_else(|| JsValue::from_str("Could not stringify JSON"))
}

#[macro_export]
macro_rules! pure_info {
    ($($arg:tt)*) => {
        tracing::info!(target: "pure_log", "{}", format_args!($($arg)*))
    }
}
