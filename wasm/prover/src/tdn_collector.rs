use base64::prelude::BASE64_URL_SAFE;
use base64::{prelude::BASE64_STANDARD, Engine as _};
use futures::channel::oneshot;
use js_sys::{Promise, Uint8Array};
use serde::{Deserialize, Serialize};
use tdn_prover::tls::{ProverConfig, TdnProver};
use wasm_bindgen_futures::{spawn_local, JsFuture};
use web_time::Instant;

use ws_stream_wasm::*;

use crate::hyper_io::FuturesIo;
use crate::request_opt::RequestOptions;
use crate::requests::{ClientType, NotarizationSessionRequest, NotarizationSessionResponse};

pub use wasm_bindgen_rayon::init_thread_pool;

use crate::fetch_as_json_string;
pub use crate::request_opt::VerifyResult;
use futures::AsyncWriteExt;
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, StatusCode};

use strum::EnumMessage;
use url::Url;
use wasm_bindgen::prelude::*;
use web_sys::{window, Headers, RequestInit, RequestMode};

use tracing::{debug, info};

#[derive(strum_macros::EnumMessage, Debug, Clone, Copy)]
enum CollectorPhases {
    #[strum(message = "Connect application server with websocket proxy")]
    ConnectWsProxy,
    #[strum(message = "Build prover config")]
    BuildProverConfig,
    #[strum(message = "Set up prover")]
    SetUpProver,
    #[strum(message = "Bind the prover to the server connection")]
    BindProverToConnection,
    #[strum(message = "Spawn the prover thread")]
    SpawnProverThread,
    #[strum(message = "Attach the hyper HTTP client to the TLS connection")]
    AttachHttpClient,
    #[strum(message = "Spawn the HTTP task to be run concurrently")]
    SpawnHttpTask,
    #[strum(message = "Build request")]
    BuildRequest,
    #[strum(message = "Start MPC-TLS connection with the server")]
    StartMpcConnection,
    #[strum(message = "Received response from the server")]
    ReceivedResponse,
    #[strum(message = "Parsing response from the server")]
    ParseResponse,
    #[strum(message = "Close the connection to the server")]
    CloseConnection,
    #[strum(message = "Taking TLS results from the prover")]
    TakeTlsResults,
    #[strum(message = "Start notarization")]
    StartNotarization,
}

fn log_phase(phase: CollectorPhases) {
    info!("tlsn-js {}: {}", phase as u8, phase.get_message().unwrap());
}

#[wasm_bindgen]
pub async fn tdn_collect(
    target_url_str: &str,
    val: JsValue,
    commitment_pwd_proof_base64: &str,
    pub_key_consumer_base64: &str,
) -> Result<String, JsValue> {
    debug!("target_url: {}", target_url_str);
    let target_url = Url::parse(target_url_str)
        .map_err(|e| JsValue::from_str(&format!("Could not parse target_url: {:?}", e)))?;

    debug!(
        "target_url.host: {}",
        target_url
            .host()
            .ok_or(JsValue::from_str("Could not get target host"))?
    );
    let options: RequestOptions = serde_wasm_bindgen::from_value(val)
        .map_err(|e| JsValue::from_str(&format!("Could not deserialize options: {:?}", e)))?;
    debug!("options.notary_url: {}", options.notary_url.as_str());

    // Re-encode base64 params into URL safe ones.
    let commitment_pwd_proof = BASE64_STANDARD
        .decode(commitment_pwd_proof_base64)
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Could not decode commitment_pwd_proof_base64: {:?}",
                e
            ))
        })?;
    let commitment_pwd_proof_base64 = BASE64_URL_SAFE.encode(&commitment_pwd_proof);

    let pub_key_consumer = BASE64_STANDARD
        .decode(pub_key_consumer_base64)
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Could not decode pub_key_consumer_base64: {:?}",
                e
            ))
        })?;
    let pub_key_consumer_base64 = BASE64_URL_SAFE.encode(&pub_key_consumer);

    let start_time = Instant::now();

    /*
     * Connect Notary with websocket
     */

    let mut opts = RequestInit::new();
    opts.method("POST");
    // opts.method("GET");
    opts.mode(RequestMode::Cors);

    // set headers
    let headers = Headers::new()
        .map_err(|e| JsValue::from_str(&format!("Could not create headers: {:?}", e)))?;
    let notary_url = Url::parse(options.notary_url.as_str())
        .map_err(|e| JsValue::from_str(&format!("Could not parse notary_url: {:?}", e)))?;
    let notary_ssl = notary_url.scheme() == "https" || notary_url.scheme() == "wss";
    let notary_host = notary_url.authority();
    let notary_path = notary_url.path();
    let notary_path_str = if notary_path == "/" { "" } else { notary_path };

    headers
        .append("Host", notary_host)
        .map_err(|e| JsValue::from_str(&format!("Could not append Host header: {:?}", e)))?;
    headers
        .append("Content-Type", "application/json")
        .map_err(|e| {
            JsValue::from_str(&format!("Could not append Content-Type header: {:?}", e))
        })?;
    opts.headers(&headers);

    info!("notary_host: {}", notary_host);
    // set body
    let payload = serde_json::to_string(&NotarizationSessionRequest {
        client_type: ClientType::Websocket,
        max_sent_data: options.max_sent_data,
        max_recv_data: options.max_recv_data,
    })
    .map_err(|e| JsValue::from_str(&format!("Could not serialize request: {:?}", e)))?;
    opts.body(Some(&JsValue::from_str(&payload)));

    // url
    let url = format!(
        "{}://{}{}/session",
        if notary_ssl { "https" } else { "http" },
        notary_host,
        notary_path_str
    );
    debug!("Request: {}", url);
    let rust_string = fetch_as_json_string(&url, &opts)
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not fetch session: {:?}", e)))?;
    let session_creation_response =
        serde_json::from_str::<NotarizationSessionResponse>(&rust_string)
            .map_err(|e| JsValue::from_str(&format!("Could not deserialize response: {:?}", e)))?;
    debug!("Response: {}", rust_string);

    debug!("TDN collect response: {:?}", session_creation_response,);
    let notary_wss_url = format!(
        "{}://{}{}/tdn-collect?sessionId={}&commitmentPwdProofBase64={}&pubKeyConsumerBase64={}",
        if notary_ssl { "wss" } else { "ws" },
        notary_host,
        notary_path_str,
        session_creation_response.session_id,
        commitment_pwd_proof_base64,
        pub_key_consumer_base64,
    );
    let (_, notary_ws_stream) = WsMeta::connect(notary_wss_url, None)
        .await
        .expect_throw("assume the notary ws connection succeeds");
    let notary_ws_stream_into = notary_ws_stream.into_io();

    log_phase(CollectorPhases::BuildProverConfig);

    let target_host = target_url
        .host_str()
        .ok_or(JsValue::from_str("Could not get target host"))?;

    // Basic default prover config
    let mut builder = ProverConfig::builder();

    if let Some(max_sent_data) = options.max_sent_data {
        builder.max_sent_data(max_sent_data);
    }
    if let Some(max_recv_data) = options.max_recv_data {
        builder.max_recv_data(max_recv_data);
    }
    let config = builder
        .id(session_creation_response.session_id)
        .server_dns(target_host)
        .build()
        .map_err(|e| JsValue::from_str(&format!("Could not build prover config: {:?}", e)))?;

    // Create a Prover and set it up with the Notary
    // This will set up the MPC backend prior to connecting to the server.
    log_phase(CollectorPhases::SetUpProver);
    let prover = TdnProver::new(config)
        .setup(notary_ws_stream_into)
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not set up prover: {:?}", e)))?;

    /*
       Connect Application Server with websocket proxy
    */
    log_phase(CollectorPhases::ConnectWsProxy);

    let (_, client_ws_stream) = WsMeta::connect(options.websocket_proxy_url, None)
        .await
        .expect_throw("assume the client ws connection succeeds");

    // Bind the Prover to the server connection.
    // The returned `mpc_tls_connection` is an MPC TLS connection to the Server: all data written
    // to/read from it will be encrypted/decrypted using MPC with the Notary.
    log_phase(CollectorPhases::BindProverToConnection);
    let (mpc_tls_connection, prover_fut) =
        prover.connect(client_ws_stream.into_io()).await.unwrap();
    let mpc_tls_connection = unsafe { FuturesIo::new(mpc_tls_connection) };

    let prover_ctrl = prover_fut.control();

    log_phase(CollectorPhases::SpawnProverThread);
    let (prover_sender, prover_receiver) = oneshot::channel();
    let handled_prover_fut = async {
        let result = prover_fut.await;
        let _ = prover_sender.send(result);
    };
    spawn_local(handled_prover_fut);

    // Attach the hyper HTTP client to the TLS connection
    log_phase(CollectorPhases::AttachHttpClient);
    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(mpc_tls_connection)
            .await
            .map_err(|e| JsValue::from_str(&format!("Could not handshake: {:?}", e)))?;

    // Spawn the HTTP task to be run concurrently
    log_phase(CollectorPhases::SpawnHttpTask);
    let (connection_sender, connection_receiver) = oneshot::channel();
    let connection_fut = connection.without_shutdown();
    let handled_connection_fut = async {
        let result = connection_fut.await;
        let _ = connection_sender.send(result);
    };
    spawn_local(handled_connection_fut);

    log_phase(CollectorPhases::BuildRequest);
    let mut req_with_header = Request::builder()
        .uri(target_url_str)
        .method(options.method.as_str());

    for (key, value) in options.headers {
        info!("adding header: {} - {}", key.as_str(), value.as_str());
        req_with_header = req_with_header.header(key.as_str(), value.as_str());
    }

    let req_with_body = if options.body.is_empty() {
        info!("empty body");
        req_with_header.body(Full::new(Bytes::default()))
    } else {
        info!("added body - {}", options.body.as_str());
        req_with_header.body(Full::from(options.body))
    };

    let unwrapped_request = req_with_body
        .map_err(|e| JsValue::from_str(&format!("Could not build request: {:?}", e)))?;

    log_phase(CollectorPhases::StartMpcConnection);

    // Defer decryption of the response.
    prover_ctrl
        .defer_decryption()
        .await
        .map_err(|e| JsValue::from_str(&format!("failed to enable deferred decryption: {}", e)))?;

    // Send the request to the Server and get a response via the MPC TLS connection
    let response = request_sender
        .send_request(unwrapped_request)
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not send request: {:?}", e)))?;

    log_phase(CollectorPhases::ReceivedResponse);
    if response.status() != StatusCode::OK {
        return Err(JsValue::from_str(&format!(
            "Response status is not OK: {:?}",
            response.status()
        )));
    }

    log_phase(CollectorPhases::ParseResponse);
    // Pretty printing :)
    let payload = response
        .into_body()
        .collect()
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not get response body: {:?}", e)))?
        .to_bytes();
    let parsed = serde_json::from_str::<serde_json::Value>(&String::from_utf8_lossy(&payload))
        .map_err(|e| JsValue::from_str(&format!("Could not parse response: {:?}", e)))?;
    let response_pretty = serde_json::to_string_pretty(&parsed)
        .map_err(|e| JsValue::from_str(&format!("Could not serialize response: {:?}", e)))?;
    info!("Response: {}", response_pretty);

    // Close the connection to the server
    log_phase(CollectorPhases::CloseConnection);
    let mut client_socket = connection_receiver
        .await
        .map_err(|e| {
            JsValue::from_str(&format!(
                "Could not receive from connection_receiver: {:?}",
                e
            ))
        })?
        .map_err(|e| JsValue::from_str(&format!("Could not get TlsConnection: {:?}", e)))?
        .io
        .into_inner();

    // The Prover task should be done now, so we can grab it.
    log_phase(CollectorPhases::TakeTlsResults);
    let prover = prover_receiver
        .await
        .map_err(|e| {
            JsValue::from_str(&format!("Could not receive from prover_receiver: {:?}", e))
        })?
        .map_err(|e| JsValue::from_str(&format!("Could not get Prover: {:?}", e)))?;

    let tdn_collect_leader_result = prover.take_collection_result();

    client_socket
        .close()
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not close socket: {:?}", e)))?;

    let res = serde_json::to_string_pretty(&tdn_collect_leader_result).map_err(|e| {
        JsValue::from_str(&format!(
            "Could not serialize TDN collect leader result: {:?}",
            e
        ))
    })?;
    info!("TDN collect leader result: {}", res);

    // Start notarization. Request a signature from Notary.
    log_phase(CollectorPhases::StartNotarization);
    let prover = prover.start_notarize();
    let signed_proof_notary = prover
        .notarize(commitment_pwd_proof, pub_key_consumer)
        .await
        .map_err(|e| JsValue::from_str(&format!("Could not notarize: {:?}", e)))?;

    info!("TDN notarization result: {:?}", signed_proof_notary);

    let _session_materials = TdnSessionMaterials {
        session: "El Psy Congroo from TDN!".to_owned(),
    };

    let duration = start_time.elapsed();
    info!("!@# request took {} seconds", duration.as_secs());

    Ok(res)
}

#[wasm_bindgen]
pub fn bytes_to_base64(bytes: Uint8Array) -> String {
    let byte_vec = bytes.to_vec();
    let base64_str = BASE64_STANDARD.encode(&byte_vec);
    return base64_str;
}

pub async fn sleep_async(ms: i32) {
    let promise = Promise::new(&mut |resolve, _| {
        window()
            .unwrap()
            .set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms)
            .unwrap();
    });
    let _ = JsFuture::from(promise).await;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TdnSessionMaterials {
    session: String,
}
