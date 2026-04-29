use std::env;

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, SwarmBuilder,
    identity,
    request_response::{self, Event, ProtocolSupport},
    swarm::{NetworkBehaviour, SwarmEvent},
};

use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
struct PingRequest {
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PingResponse{
    message: String,
}

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    req_res: request_response::json::Behaviour<PingRequest, PingResponse>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage:");
        eprintln!("  cargo run -- listen <port>");
        eprintln!("  cargo run -- dial <multiaddr>");
        std::process::exit(1);
    }

    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    println!("Local peerId: {}", local_peer_id);

    let behaviour = MyBehaviour {
        req_res: request_response::json::Behaviour::new(
            [(
                libp2p::StreamProtocol::new("/belal/pingpong/1"),
                ProtocolSupport::Full,
            )],
            request_response::Config::default(),
        ),      
    };
    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
    .with_tokio()
    .with_tcp(
        Default::default(),
        libp2p::noise::Config::new,
        libp2p::yamux::Config::default,
    )?
    .with_behaviour(|_| behaviour)?
    .build();

    let mut sent_ping = false;

    match args[1].as_str() {
        "listen" => {
            let port = args
            .get(2)
            .expect("missing port")
            .parse::<u16>()
            .expect("Invalid port");

        let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse()?;
        swarm.listen_on(listen_addr.clone())?;
        println!("Listening mode on port {}", port);
        }

        "dial" => {
            let addr: Multiaddr = args.get(2).expect("Missing multiAddr").parse()?;
            println!("Dial mode to {}", addr);
            swarm.dial(addr)?;
        }

        other => {
            eprintln!("Unkwon mode: {}", other);
            std::process::exit(1);
        }
    }

    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, ..} => {
                println!("Now listening on {}", address);
            }
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, ..} => {
                println!("Connected to peer: {peer_id} via {endpoint:?}");
                if args[1] == "dial" && !sent_ping {
                    let req = PingRequest {
                        message: "ping".to_string(),
                    };
                    let request_id = swarm.behaviour_mut().req_res.send_request(&peer_id, req);
                    println!("Sent ping: {:?}", request_id);
                    sent_ping = true;
                }
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::ReqRes(event)) => match event {
                request_response::Event::Message { peer, message, .. } => match message {
                    request_response::Message::Request {request, channel, request_id} => {
                        println!("Got request from: {}: {:?}, request_id: {:?}", peer, request, request_id);
                        let response = PingResponse {
                            message: "Pong".to_string(),
                        };
                        if let Err(err) = swarm.behaviour_mut().req_res.send_response(channel, response) {
                            eprintln!("Faild to send response: {:?}", err);
                        } else {
                            println!("Sent pong");
                        }
                    }
                    request_response::Message::Response { request_id, response } => {
                        println!("Got response for request: {:?}: {:?}", request_id, response);
                    }
                },
                request_response::Event::OutboundFailure { peer, request_id, error, .. } => {
                    eprintln!("Outbound failure to peer: {}, for request: {:?}: {:?}", peer, request_id, error);
                }
                request_response::Event::InboundFailure { peer, request_id, error, .. } => {
                    eprintln!("Inbound failure from peer: {} for request: {:?}: {:?}", peer, request_id, error);
                }
                request_response::Event::ResponseSent { peer, request_id, .. } => {
                    println!("Response sent to: {}, for request {:?}", peer, request_id);
                }
            }
            
            event => {
                println!("Swarm event: {event:?}");
            }
            
        }
    }

    Ok(())
}