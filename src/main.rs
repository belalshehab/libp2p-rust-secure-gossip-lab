use std::env;

use futures::StreamExt;

use libp2p::{Multiaddr, PeerId, identity};
use libp2p_secure_gossip_lab::identity::{generate_demo_keys_file, load_keys_file, load_node_identity, load_trusted_keys};
use libp2p_secure_gossip_lab::{build_swarm, handle_event};
use libp2p_secure_gossip_lab::message::{self, signing_payload};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::Signer;
use tokio::io::{self, AsyncBufReadExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if !std::path::Path::new("keys/demo_keys.json").exists() {
        generate_demo_keys_file("keys/demo_keys.json")?;
    }

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage:");
        eprintln!("  cargo run -- <port>");
        eprintln!("  cargo run -- <port> --node-id node1");
        eprintln!("  cargo run -- <port> --no-mdns <multiaddr>");
        std::process::exit(1);
    }

    let port = args
        .get(1)
        .expect("Missing port")
        .parse::<u16>()
        .expect("Invalid port");

    let node_id: Option<String> = args.windows(2)
        .find(|w| w[0] == "--node-id")
        .map(|w| w[1].clone());

    let no_mdns_pos = args.iter().position(|a| a == "--no-mdns");
    let no_mdns = no_mdns_pos.is_some();

    let manual_peer_addr: Option<Multiaddr> = if let Some(pos) = no_mdns_pos {
        args.get(pos + 1).map(|s| s.parse()).transpose()?
    } else {
        None
    };

    let keys = load_keys_file("keys/demo_keys.json")?;
    let trusted_keys = load_trusted_keys(&keys)?;

    let node_identity = if let Some(ref id) = node_id {
        Some(load_node_identity(&keys, id)?)
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
                    let (sender_id, signature) = if let Some(ref identity) = node_identity {
                        let sig_bytes = identity.signing_key.sign(&signing_payload(&identity.node_id, &line));
                        (identity.node_id.clone(), STANDARD.encode(sig_bytes.to_bytes()))
                    } else {
                        (local_peer_id.to_string(), String::new())
                    };
                    let envelope = message::SignedChatMessage {
                        sender_id,
                        payload: line,
                        signature,
                    };
                    let bytes = serde_json::to_vec(&envelope).expect("Serialize failed");

                    if let Err(err) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), bytes) {
                        eprintln!("Publish error: {err}");
                    }
                }
            }

            event = swarm.select_next_some() => {
                handle_event(event, &mut swarm, local_peer_id, &trusted_keys);
            }
        }
    }

    #[allow(unreachable_code)]
    Ok(())
}
