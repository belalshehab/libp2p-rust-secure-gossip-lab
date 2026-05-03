use std::env;

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, SwarmBuilder,
    identity,
    mdns,
    gossipsub,
    swarm::{NetworkBehaviour, SwarmEvent},
};

use tokio::io::{self, AsyncBufReadExt};

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    mdns: mdns::tokio::Behaviour,
    gossipsub: gossipsub::Behaviour,
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

    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub::Config::default(),
    )?;

    let topic = gossipsub::IdentTopic::new("Chat");
    gossipsub.subscribe(&topic)?;

    let behaviour = MyBehaviour {
        mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?,
        gossipsub,
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

    let port = args
        .get(1)
        .expect("Missing port")
        .parse::<u16>()
        .expect("Invalid port");

    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse()?;
    swarm.listen_on(listen_addr.clone())?;
    println!("Listening on port {}", port);

    let mut stdin = io::BufReader::new(io::stdin()).lines();

    loop {
        tokio::select! {
            line = stdin.next_line() => {

                let line = line?;
                if let Some(line) = line {
                    if let Err(err) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), line.as_bytes()) {
                        eprintln!("Publish error: {err}");
                    }
                }
            }

            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::NewListenAddr { address, ..} => {
                        println!("Now listening on {}", address);
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, ..} => {
                        println!("Connected to peer: {peer_id} via {endpoint:?}");
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                    }

                    SwarmEvent::ConnectionClosed { peer_id, cause, num_established, ..} => {
                        println!("Disconnected from peer: {peer_id}, cause: {cause:?}");
                        if num_established == 0 {
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    }

                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(event)) => match event {
                        mdns::Event::Discovered(peers) => {
                            println!("Discoverd {} new peers", {peers.len()});
                            for (peer, addr) in peers {
                                if peer == local_peer_id {
                                    continue;
                                }
                                println!("Discoverd peer: {:?}, addr: {:?}", peer, addr);
                                let should_dial = local_peer_id.to_string() < peer.to_string();
                                if should_dial {
                                    println!("we will dial");
                                    if let Err(err) = swarm.dial(addr.clone()) {
                                        eprintln!("Failed to dial discovered peer {peer}: {err}");
                                    } 
                                } else {
                                    println!("we will wait for them to dial us");
                                }
                            }
                        },
                        mdns::Event::Expired(peers) => {
                            println!("Expired {} new peers", {peers.len()});
                            for (peer, addr) in &peers {
                                println!("Expired peer: {:?}, addr: {:?}", peer, addr);
                            }
                        },
                    }

                    SwarmEvent::Behaviour(MyBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                        propagation_source,
                        message_id,
                        message,
                    })) => {
                        println!(
                            "Got message from: {propagation_source}: '{}', with id: {message_id}",
                            String::from_utf8_lossy(&message.data)
                        );
                    }

                    event => {
                        println!("Swarm event: {event:?}");
                    }
                }
            }
        }
    }

    Ok(())
}
