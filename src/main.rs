use esp_idf_hal::delay;
use esp_idf_hal::modem::Modem;
use esp_idf_hal::peripherals::Peripherals;
use esp_idf_svc::eventloop::EspSystemEventLoop;
use esp_idf_svc::http::server::{Configuration as HttpServerConfig, EspHttpServer};
use esp_idf_svc::mqtt::client::*;
use esp_idf_svc::nvs::EspDefaultNvsPartition;
use esp_idf_svc::sys::EspError;
use esp_idf_svc::wifi::{BlockingWifi, EspWifi};

use embedded_svc::{
    http::{Headers, Method},
    io::{Read, Write},
    wifi::{AccessPointConfiguration, AuthMethod, Configuration},
};

use serde::Deserialize;

use log::*;
use std::thread::sleep;
use std::time::Duration;

#[derive(Deserialize)]
struct FormData<'a> {
    url: &'a str,
    topic: &'a str,
    user: &'a str,
    password: &'a str,
}

// max payload length
const MAX_LEN: usize = 128;

const PASSWORD: &str = "PASSWORDIPOSTINGITHUB";
static INDEX_HTML: &str = include_str!("http_server_page.html");

fn main() -> anyhow::Result<()> {
    esp_idf_sys::link_patches();
    esp_idf_svc::log::EspLogger::initialize_default();

    let peripherals = Peripherals::take().unwrap();

    let sys_loop = EspSystemEventLoop::take().unwrap();
    let nvs = EspDefaultNvsPartition::take().unwrap();

    let _wifi = create_wifi(&sys_loop, &nvs, peripherals.modem)?;

    let server_configuration = esp_idf_svc::http::server::Configuration {
        stack_size: 10240,
        ..Default::default()
    };

    let mut httpserver = EspHttpServer::new(&server_configuration)?;

    httpserver.fn_handler("/", Method::Get, |req| {
        req.into_ok_response()?
            .write_all(INDEX_HTML.as_bytes())
            .map(|_| ())
    })?;

    // make it so, that if any attempt to post comes in, it redirects to another post method
    // that way I could create a "successfull" page as the first post method and that creates the
    // server. Since the server only leaves the loop, if it errors out, then it could redirect to
    // index again, if it had an error.
    // OR
    // the mqtt server could be started in its own thread, so that it would exit with an access.
    // Then it could write the response depending on success or failure
    httpserver.fn_handler::<anyhow::Error, _>("/post", Method::Post, |mut req| {
        let len = req.content_len().unwrap_or(0) as usize;

        if len > MAX_LEN {
            req.into_status_response(413)?
                .write_all("Request too big".as_bytes())?;
            return Ok(());
        }

        let mut buf = vec![0; len];
        req.read_exact(&mut buf)?;
        let mut resp = req.into_ok_response()?;

        match serde_json::from_slice::<FormData>(&buf) {
            Ok(form) => match runmqtt(form.url, form.topic, form.user, form.password) {
                Ok(_) => resp.write_all("Connection successfull!".as_bytes())?,
                Err(err) => {
                    write!(
                        resp,
                        "failed to create server with URL {} and topic {}\nError: {}",
                        form.url, form.topic, err,
                    )?;
                }
            },
            Err(err) => {
                resp.write_all(err.to_string().as_bytes())?;
            }
        };

        anyhow::Ok(())
    })?;

    // Sobald ein post req
    // einen mqtt server erstellen

    // Hier den Post request handler hinbauen, der mqtt_url und mqtt_topic überschreibt (später
    // auch id und pw)
    // Wenn der Post request den statuscode 200 hat, dann wird der MQTT Client mit den obigen
    // Zugangsdaten gestartet.

    // this should never return
    //let _ = runmqtt("mqtt://localhost:1883", "test")?;
    core::mem::forget(httpserver);
    loop {
        //delay::Ets::delay_ms(1000);
        sleep(Duration::from_millis(100));
    }

    // this will free up some space from main

    // Kann ich abhängig davon, ob der client gestartet hat (und funktioniert) auf der http page
    // anzeigen, dass es funktioniert hat und eine connection da ist? (optional, weil ich eine
    // inital message über mqtt senden könnte.)
    //anyhow::Ok(())
}

fn runmqtt(url: &str, topic: &str, user: &str, password: &str) -> Result<(), EspError> {
    let (mut mqtt_client, mut mqtt_conn) = EspMqttClient::new(
        url,
        &MqttClientConfiguration {
            username: Some(user),
            password: Some(password),
            connection_refresh_interval: Duration::new(0, 1000),
            ..Default::default()
        },
    )?;

    // the thread spawned in here will only live as long as the scope exists
    std::thread::scope(|s| {
        let payload = format!("AHHHHH");
        std::thread::Builder::new()
            .stack_size(6000)
            .spawn_scoped(s, move || {
                info!("MQTT Listening for messages");

                while let Ok(event) = mqtt_conn.next() {
                    info!("[Queue] Event: {}", event.payload());
                }

                info!("Connection closed");
            })
            .unwrap();

        mqtt_client
            .enqueue(topic, QoS::AtMostOnce, false, "Initial message".as_bytes())
            .expect("enqueing failed");

        loop {
            mqtt_client
                .enqueue(topic, QoS::AtMostOnce, false, payload.as_bytes())
                .expect("enqueing failed");

            info!("Published \"{payload}\" to topic \"{topic}\"");

            let sleep_milis: u32 = 100;
            info!("Now sleeping for {sleep_milis}ms...");
            delay::Ets::delay_ms(sleep_milis);
        }
    })
}

fn create_wifi(
    sys_loop: &EspSystemEventLoop,
    nvs: &EspDefaultNvsPartition,
    modem: Modem,
) -> Result<BlockingWifi<EspWifi<'static>>, EspError> {
    let esp_wifi = EspWifi::new(modem, sys_loop.clone(), Some(nvs.clone()))?;
    let mut wifi = BlockingWifi::wrap(esp_wifi, sys_loop.clone())?;

    let config = Configuration::AccessPoint(AccessPointConfiguration {
        ssid: "EspWifi".try_into().unwrap(),
        auth_method: AuthMethod::WPA3Personal,
        password: PASSWORD.try_into().unwrap(),
        ..Default::default()
    });

    wifi.set_configuration(&config)?;

    wifi.start()?;

    // Wait until the network interface is up
    wifi.wait_netif_up()?;

    while !wifi.is_up().unwrap() {
        // Get and print connection configuration
        let config = wifi.get_configuration().unwrap();
        println!("Waiting to set up {:?}", config);
    }

    Ok(wifi)
}
