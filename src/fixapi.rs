use std::{
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::Duration,
};

use async_std::{
    channel::{bounded, Receiver},
    io::{BufWriter, WriteExt},
    net::TcpStream,
    stream::{self, StreamExt},
    sync::RwLock,
    task,
};

use crate::socket::Socket;
use crate::types::{Config, Error, Field, SubID, DELIMITER};
use crate::{
    messages::{HeartbeatReq, LogonReq, LogoutReq, RequestMessage, ResponseMessage, TestReq},
    types::ConnectionHandler,
};

pub struct FixApi {
    config: Config,
    stream: Option<Arc<TcpStream>>,
    seq: Arc<AtomicU32>,
    sub_id: SubID,

    is_connected: Arc<AtomicBool>,

    res_receiver: Option<Receiver<ResponseMessage>>,
    notifier: Option<Receiver<()>>,

    container: Arc<RwLock<Vec<ResponseMessage>>>,
    //callback
    connection_handler: Option<Arc<dyn ConnectionHandler + Send + Sync>>,
}

impl FixApi {
    pub fn new(
        sub_id: SubID,
        host: String,
        login: String,
        password: String,
        broker: String,
        heartbeat_interval: Option<u32>,
    ) -> Self {
        Self {
            config: Config::new(
                host,
                login,
                password,
                broker,
                heartbeat_interval.unwrap_or(30),
            ),
            stream: None,
            res_receiver: None,
            notifier: None,
            is_connected: Arc::new(AtomicBool::new(false)),
            seq: Arc::new(AtomicU32::new(1)),
            container: Arc::new(RwLock::new(Vec::new())),
            sub_id,
            connection_handler: None,
        }
    }

    pub fn register_connection_handler<T: ConnectionHandler + Send + Sync + 'static>(
        &mut self,
        handler: T,
    ) {
        self.connection_handler = Some(Arc::new(handler));
    }

    pub async fn disconnect(&mut self) -> Result<(), Error> {
        if let Some(stream) = &mut self.stream {
            stream.shutdown(std::net::Shutdown::Both)?;
        }
        self.stream = None;
        self.res_receiver = None;
        self.notifier = None;
        self.is_connected.store(false, Ordering::Relaxed);
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<(), Error> {
        let (sender, receiver) = bounded(1);
        let mut socket = Socket::connect(
            self.config.host.as_str(),
            if self.sub_id == SubID::QUOTE {
                5201
            } else {
                5202
            },
            sender,
        )
        .await?;
        self.is_connected.store(true, Ordering::Relaxed);
        log::debug!("stream connected");

        // notify connection
        if let Some(handler) = self.connection_handler.clone() {
            task::spawn(async move {
                handler.on_connect().await;
            });
        }

        self.res_receiver = Some(receiver);
        self.stream = Some(socket.stream.clone());

        let is_connected = self.is_connected.clone();

        let handler = self.connection_handler.clone();
        let _ = task::spawn(async move {
            socket.recv_loop(is_connected, handler).await.unwrap();
        });

        Ok(())
    }

    pub async fn send_message<R: RequestMessage>(&mut self, req: R) -> Result<(), Error> {
        let req = req.build(
            self.sub_id,
            self.seq.fetch_add(1, Ordering::Relaxed),
            DELIMITER,
            &self.config,
        );
        if let Some(stream) = self.stream.as_mut() {
            log::debug!("Send request : {}", req);
            let mut writer = BufWriter::new(stream.as_ref());
            writer.write_all(req.as_bytes()).await?;
            writer.flush().await?;
        }

        Ok(())
    }

    pub fn is_connected(&self) -> bool {
        self.is_connected.load(Ordering::Relaxed)
    }

    //
    // request
    //
    pub async fn heartbeat(&mut self) -> Result<(), Error> {
        self.send_message(HeartbeatReq::default()).await?;
        Ok(())
    }

    pub async fn logon(&mut self) -> Result<(), Error> {
        // TODO check the connected

        self.send_message(LogonReq::default()).await?;

        // wait to receive the response
        if let Some(recv) = &self.res_receiver {
            while let Ok(response) = recv.recv().await {
                // logon response
                if response.get_message_type() == "A" {
                    //
                    if let Some(handler) = self.connection_handler.clone() {
                        task::spawn(async move {
                            handler.on_logon().await;
                        });
                    }

                    let stream = self.stream.clone().unwrap();
                    let sub_id = self.sub_id;
                    let config = self.config.clone();
                    let seq = self.seq.clone();

                    let send_request = move |req: Box<dyn RequestMessage>| {
                        let stream = stream.clone();
                        let sub_id = sub_id;
                        let config = config.clone();
                        let seq = seq.clone();
                        async move {
                            let req = req.build(
                                sub_id,
                                seq.fetch_add(1, Ordering::Relaxed),
                                DELIMITER,
                                &config,
                            );

                            let mut writer = BufWriter::new(stream.as_ref());
                            let _ = writer.write_all(req.as_bytes()).await;
                            writer.flush().await.unwrap_or_else(|e| {
                                log::error!("Failed to send the heartbeat request - {:?}", e);
                            });
                        }
                    };
                    let send_request_clone = send_request.clone();

                    let hb_interval = self.config.heart_beat as u64;

                    //
                    // send heartbeat per hb_interval
                    task::spawn(async move {
                        let mut heartbeat_stream =
                            stream::interval(Duration::from_secs(hb_interval));

                        while let Some(_) = heartbeat_stream.next().await {
                            let req = HeartbeatReq::default();
                            send_request(Box::new(req)).await;
                            log::debug!("Sent the heartbeat");
                        }
                    });

                    //
                    // handle the responses

                    // notifier
                    let (tx, rx) = bounded(1);
                    self.notifier = Some(rx);
                    let recv = self.res_receiver.clone().unwrap();
                    let cont = self.container.clone();

                    task::spawn(async move {
                        while let Ok(res) = recv.recv().await {
                            // notify? or send? via channel?
                            match res.get_message_type() {
                                "1" => {
                                    // send back with test request id
                                    if let Some(test_req_id) = res.get_field_value(Field::TestReqID)
                                    {
                                        send_request_clone(Box::new(TestReq::new(test_req_id)))
                                            .await;
                                        log::debug!("Sent the heartbeat from test_req_id");
                                    }
                                }
                                _ => {
                                    // store the response in container.
                                    let mut cont = cont.write().await;
                                    log::info!("{}", res.get_message());

                                    // TODO
                                    // cont.push(res);
                                    // tx.send(()).await.unwrap_or_else(|e| {
                                    //     log::error!(
                                    //         "Failed to notify that the response is received - {:?}",
                                    //         e
                                    //     );
                                    // });
                                }
                            }
                        }
                    });

                    break;
                }
            }
        }

        Ok(())
    }

    pub async fn logout(&mut self) -> Result<(), Error> {
        self.send_message(LogoutReq::default()).await?;
        Ok(())
    }
}
