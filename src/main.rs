use std::env;

use futures::StreamExt;

use libp2p::{Multiaddr, PeerId, identity};
use libp2p_secure_gossip_lab::{build_swarm, handle_event};

use tokio::io::{self, AsyncBufReadExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage:");
        eprintln!("  cargo run -- <port>");
        eprintln!("  cargo run -- <port> --no-mdns <multiaddr>");
        std::process::exit(1);
    }

    let port = args
        .get(1)
        .expect("Missing port")
        .parse::<u16>()
        .expect("Invalid port");

    let no_mdns = args.get(2).is_some_and(|arg| arg == "--no-mdns");

    let manual_peer_addr: Option<Multiaddr> = if no_mdns {
        args.get(3).map(|s| s.parse()).transpose()?
    } else {
        None
    };

    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    let (mut swarm, topic) = build_swarm(local_key, no_mdns)?;

    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{port}").parse()?;
    swarm.listen_on(listen_addr)?;
    println!("Listening on port {}", port);
    if let Some(addr) = manual_peer_addr {
        println!("mdns disabled. Dialing manual peer: {addr}");

        if let Err(err) = swarm.dial(addr.clone()) {
            eprintln!("Failed to manually dial: {addr}: {err}");
        }
    }

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
                handle_event(event, &mut swarm, local_peer_id);
            }
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}
