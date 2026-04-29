use std::env;

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, SwarmBuilder,
    identity,
    mdns,
    swarm::{NetworkBehaviour, SwarmEvent},
};

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    mdns: libp2p::mdns::tokio::Behaviour,
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
        mdns: libp2p::mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?,
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

    let port = args.get(1)
        .expect("Missing port")
        .parse::<u16>()
        .expect("Invalid port");

    let dial = args.get(2)
        .expect("missing dial")
        .parse::<bool>()
        .expect("missing dial");
    
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse()?;
    swarm.listen_on(listen_addr.clone())?;
    println!("Listening on port {}", port);


    loop {
        match swarm.select_next_some().await {
            SwarmEvent::NewListenAddr { address, ..} => {
                println!("Now listening on {}", address);
            }
            SwarmEvent::ConnectionEstablished { peer_id, endpoint, ..} => {
                println!("Connected to peer: {peer_id} via {endpoint:?}");
            }

            SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(event)) => match event {
                mdns::Event::Discovered(peers) => {
                    println!("Discoverd {} new peers", {peers.len()});
                    for (peer, addr) in peers {
                        if peer == local_peer_id {
                            continue;
                        }
                        println!("Discoverd peer: {:?}, addr: {:?}", peer, addr);
                        if dial {
                            println!("we will dial");
                            if let Err(err) = swarm.dial(addr.clone()) {
                                eprintln!("Failed to dial discovered peer {peer}: {err}");
                            }
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

            event => {
                println!("Swarm event: {event:?}");
            }
            
        }
    }

    Ok(())
}