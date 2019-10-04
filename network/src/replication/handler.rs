//
// Copyright (c) 2019 Stegos AG
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

use super::protocol::{ReplicationCodec, ReplicationConfig};

use futures::prelude::*;
use futures::sync::mpsc;
//use libp2p_core::nodes::Substream;
use futures::future;
use futures::sink;
use futures::stream;
use libp2p_core::upgrade::{InboundUpgrade, Negotiated, OutboundUpgrade};
use libp2p_swarm::protocols_handler::{
    KeepAlive, ProtocolsHandler, ProtocolsHandlerEvent, ProtocolsHandlerUpgrErr, SubstreamProtocol,
};
use log::*;
use std::fmt;
use std::io;
use tokio::codec::Framed;
use tokio::io::{AsyncRead, AsyncWrite};

const INPUT_BUFFER_SIZE: usize = 10;
const OUTPUT_BUFFER_SIZE: usize = 10;

/// Events consumed to ReplicationHandler.
/// Sic: this structure is `pub` because it doesn't compile otherwise.
#[derive(Debug)]
pub enum HandlerInEvent {
    Connect,
    Disconnect,
}

/// Events generated by ReplicationHandler.
#[derive(Debug)]
pub enum HandlerOutEvent {
    Connected {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
    ConnectionFailed {
        error: io::Error,
    },
    Accepted {
        tx: mpsc::Sender<Vec<u8>>,
        rx: mpsc::Receiver<Vec<u8>>,
    },
}

type Message = Vec<u8>;

/// State of an active substream, opened either by us or by the remote.
/// Sic: this structure is `pub` because it doesn't compile otherwise.
enum SubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite + Send,
{
    /// A new peer.
    Registered,
    /// A request to establish connection has been received.
    InjectConnecting,
    /// Peer is connecting to a remote side.
    Connecting,
    /// Connection to a remote side has been failed.
    /// This is a transitional state for inject_dial_upgrade_error().
    ConnectionFailed { error: io::Error },
    /// Connected to a remote side.
    Connected {
        protocol: Framed<Negotiated<TSubstream>, ReplicationCodec>,
    },
    /// Accepted a remote side.
    Accepted {
        protocol: Framed<Negotiated<TSubstream>, ReplicationCodec>,
    },
    /// Forwarding network <-> mpsc::channel().
    /// Sic: Rust doesn't support Box::new() for <T> type.
    Forwarding {
        rx_forward: future::Map<
            stream::Forward<
                stream::SplitStream<Framed<Negotiated<TSubstream>, ReplicationCodec>>,
                sink::SinkMapErr<
                    futures::sync::mpsc::Sender<Vec<u8>>,
                    fn(futures::sync::mpsc::SendError<Vec<u8>>) -> io::Error,
                >,
            >,
            fn(
                (
                    stream::SplitStream<Framed<Negotiated<TSubstream>, ReplicationCodec>>,
                    sink::SinkMapErr<
                        futures::sync::mpsc::Sender<Vec<u8>>,
                        fn(futures::sync::mpsc::SendError<Vec<u8>>) -> io::Error,
                    >,
                ),
            ),
        >,
        tx_forward: future::Map<
            stream::Forward<
                stream::MapErr<futures::sync::mpsc::Receiver<Vec<u8>>, fn(()) -> io::Error>,
                stream::SplitSink<Framed<Negotiated<TSubstream>, ReplicationCodec>>,
            >,
            fn(
                (
                    stream::MapErr<futures::sync::mpsc::Receiver<Vec<u8>>, fn(()) -> io::Error>,
                    stream::SplitSink<Framed<Negotiated<TSubstream>, ReplicationCodec>>,
                ),
            ),
        >,
    },
}

fn to_io_error<E>(_e: E) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionReset, "channel")
}

impl<TSubstream> Future for SubstreamState<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite + Send,
{
    type Item = (mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>);
    type Error = ();

    fn poll(&mut self) -> Poll<Self::Item, ()> {
        match self {
            SubstreamState::Registered
            | SubstreamState::InjectConnecting
            | SubstreamState::Connecting => Ok(Async::NotReady),
            SubstreamState::Connected { .. } | SubstreamState::Accepted { .. } => {
                let protocol = match std::mem::replace(self, SubstreamState::Registered) {
                    SubstreamState::Connected { protocol }
                    | SubstreamState::Accepted { protocol } => protocol,
                    _ => unreachable!("Expected Connected|Accepted state"),
                };

                let (net_tx, net_rx) = protocol.split();
                let (node_tx, rx) = mpsc::channel::<Vec<u8>>(INPUT_BUFFER_SIZE);
                let (tx, node_rx) = mpsc::channel::<Vec<u8>>(OUTPUT_BUFFER_SIZE);
                let node_tx = node_tx.sink_map_err(to_io_error as fn(_) -> _);
                let node_rx = node_rx.map_err(to_io_error as fn(_) -> _);

                let rx_forward = net_rx.forward(node_tx).map(drop as fn(_));
                let tx_forward = node_rx.forward(net_tx).map(drop as fn(_) -> _);

                let state = SubstreamState::Forwarding {
                    rx_forward,
                    tx_forward,
                };
                std::mem::replace(self, state);
                Ok(Async::Ready((tx, rx)))
            }
            SubstreamState::Forwarding {
                tx_forward,
                rx_forward,
            } => match tx_forward.poll() {
                Ok(Async::Ready(())) => {
                    std::mem::replace(self, SubstreamState::Registered);
                    Ok(Async::NotReady)
                }
                Ok(Async::NotReady) => match rx_forward.poll() {
                    Ok(Async::Ready(())) => {
                        std::mem::replace(self, SubstreamState::Registered);
                        Ok(Async::NotReady)
                    }
                    Ok(Async::NotReady) => Ok(Async::NotReady),
                    Err(error) => {
                        error!("rx error: {:?}", error);
                        std::mem::replace(self, SubstreamState::Registered);
                        Ok(Async::NotReady)
                    }
                },
                Err(error) => {
                    error!("tx error: {:?}", error);
                    std::mem::replace(self, SubstreamState::Registered);
                    Ok(Async::NotReady)
                }
            },
            SubstreamState::ConnectionFailed { .. } => {
                // Transitional state for inject_dial_upgrade_error().
                unreachable!("ConnectionFailed is handled by upper level");
            }
        }
    }
}

pub struct ReplicationHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite + Send,
{
    /// Configuration for the floodsub protocol.
    config: ReplicationConfig,

    upstream: SubstreamState<TSubstream>,
    downstream: SubstreamState<TSubstream>,
}

impl<TSubstream> ReplicationHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite + Send,
{
    /// Builds a new `ReplicationHandler`.
    pub fn new() -> Self {
        ReplicationHandler {
            config: ReplicationConfig::new(),
            upstream: SubstreamState::Registered,
            downstream: SubstreamState::Registered,
        }
    }
}

impl<TSubstream> ProtocolsHandler for ReplicationHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite + Send,
{
    type InEvent = HandlerInEvent;
    type OutEvent = HandlerOutEvent;
    type Error = io::Error;
    type Substream = TSubstream;
    type InboundProtocol = ReplicationConfig;
    type OutboundProtocol = ReplicationConfig;
    type OutboundOpenInfo = ();

    #[inline]
    fn listen_protocol(&self) -> SubstreamProtocol<Self::InboundProtocol> {
        SubstreamProtocol::new(self.config.clone())
    }

    fn inject_fully_negotiated_inbound(
        &mut self,
        protocol: <Self::InboundProtocol as InboundUpgrade<TSubstream>>::Output,
    ) {
        match self.downstream {
            SubstreamState::Registered | SubstreamState::ConnectionFailed { .. } => {
                debug!("Accepted");
                self.downstream = SubstreamState::Accepted { protocol };
            }
            _ => {
                debug!("Rejected");
            }
        }
    }

    fn inject_fully_negotiated_outbound(
        &mut self,
        protocol: <Self::OutboundProtocol as OutboundUpgrade<TSubstream>>::Output,
        _open_info: Self::OutboundOpenInfo,
    ) {
        match self.upstream {
            SubstreamState::Connecting => {
                debug!("Connected");
                self.upstream = SubstreamState::Connected { protocol };
            }
            _ => {
                debug!("Disconnect");
            }
        }
    }

    #[inline]
    fn inject_event(&mut self, event: Self::InEvent) {
        trace!("Inject event: event={:?}", event);
        match event {
            HandlerInEvent::Connect => {
                debug!("Connecting");
                self.upstream = SubstreamState::InjectConnecting;
            }
            HandlerInEvent::Disconnect => {
                debug!("Disconnecting");
                self.upstream = SubstreamState::Registered;
            }
        }
    }

    #[inline]
    fn inject_dial_upgrade_error(
        &mut self,
        _: Self::OutboundOpenInfo,
        e: ProtocolsHandlerUpgrErr<
            <Self::OutboundProtocol as OutboundUpgrade<Self::Substream>>::Error,
        >,
    ) {
        trace!("Connection failed: {}", e);
        match self.upstream {
            SubstreamState::Connecting => {}
            _ => unreachable!("Expected Connecting state"),
        }
        let error = io::Error::new(io::ErrorKind::Other, format!("{}", e));
        self.upstream = SubstreamState::ConnectionFailed { error };
    }

    #[inline]
    fn connection_keep_alive(&self) -> KeepAlive {
        KeepAlive::Yes
    }

    fn poll(
        &mut self,
    ) -> Poll<
        ProtocolsHandlerEvent<Self::OutboundProtocol, Self::OutboundOpenInfo, Self::OutEvent>,
        io::Error,
    > {
        trace!("Poll");

        if let SubstreamState::InjectConnecting = &self.upstream {
            // Create a new substream.
            self.upstream = SubstreamState::Connecting;
            return Ok(Async::Ready(
                ProtocolsHandlerEvent::OutboundSubstreamRequest {
                    info: (),
                    protocol: SubstreamProtocol::new(self.config.clone()),
                },
            ));
        } else if let SubstreamState::ConnectionFailed { .. } = &self.upstream {
            // Substream creation failed.
            let error = match std::mem::replace(&mut self.upstream, SubstreamState::Registered) {
                SubstreamState::ConnectionFailed { error } => error,
                _ => unreachable!("Expected ConnectionFailed state"),
            };
            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                HandlerOutEvent::ConnectionFailed { error },
            )));
        };

        if let Async::Ready((tx, rx)) = self.upstream.poll().unwrap() {
            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                HandlerOutEvent::Connected { rx, tx },
            )));
        }

        if let Async::Ready((tx, rx)) = self.downstream.poll().unwrap() {
            return Ok(Async::Ready(ProtocolsHandlerEvent::Custom(
                HandlerOutEvent::Accepted { rx, tx },
            )));
        }

        Ok(Async::NotReady)
    }
}

impl<TSubstream> fmt::Debug for ReplicationHandler<TSubstream>
where
    TSubstream: AsyncRead + AsyncWrite + Send,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct("ReplicationHandler").finish()
    }
}
