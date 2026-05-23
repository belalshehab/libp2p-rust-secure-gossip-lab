use libp2p::gossipsub::{Message, MessageId};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::{
    PeerId, Swarm, SwarmBuilder, gossipsub,
    identity::Keypair,
    mdns,
    swarm::{NetworkBehaviour, SwarmEvent},
};

#[derive(NetworkBehaviour)]
pub struct SecureGossipBehaviour {
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub gossipsub: gossipsub::Behaviour,
}

pub fn build_swarm(
    local_key: Keypair,
    no_mdns: bool,
) -> Result<(Swarm<SecureGossipBehaviour>, gossipsub::IdentTopic), Box<dyn std::error::Error>> {
    let local_peer_id = PeerId::from(local_key.public());

    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub::Config::default(),
    )?;

    let topic = gossipsub::IdentTopic::new("secure-gossip-lab/v1/chat");
    gossipsub.subscribe(&topic)?;

    let mdns_behaviour = if no_mdns {
        Toggle::from(None)
    } else {
        Toggle::from(Some(mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            local_peer_id,
        )?))
    };

    let behaviour = SecureGossipBehaviour {
        mdns: mdns_behaviour,
        gossipsub,
    };

    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            Default::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|_| behaviour)?
        .build();
    Ok((swarm, topic))
}

pub fn handle_event(
    event: SwarmEvent<SecureGossipBehaviourEvent>,
    swarm: &mut Swarm<SecureGossipBehaviour>,
    local_peer_id: PeerId,
) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            println!("Now listening on {}", address);
        }
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            println!("Connected to peer: {peer_id} via {endpoint:?}");
            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
        }

        SwarmEvent::ConnectionClosed {
            peer_id,
            cause,
            num_established,
            ..
        } => {
            println!("Disconnected from peer: {peer_id}, cause: {cause:?}");
            if num_established == 0 {
                swarm
                    .behaviour_mut()
                    .gossipsub
                    .remove_explicit_peer(&peer_id);
            }
        }

        SwarmEvent::Behaviour(SecureGossipBehaviourEvent::Mdns(event)) => {
            handle_mdns(event, swarm, local_peer_id)
        }

        SwarmEvent::Behaviour(SecureGossipBehaviourEvent::Gossipsub(
            gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            },
        )) => {
            handle_gossipsub_message(propagation_source, message_id, message);
        }

        event => {
            println!("Swarm event: {event:?}");
        }
    }
}

fn handle_mdns(
    event: mdns::Event,
    swarm: &mut Swarm<SecureGossipBehaviour>,
    local_peer_id: PeerId,
) {
    match event {
        mdns::Event::Discovered(peers) => {
            println!("Discovered {} new peers", peers.len());
            for (peer, addr) in peers {
                if peer == local_peer_id {
                    continue;
                }
                println!("Discovered peer: {:?}, addr: {:?}", peer, addr);
                // Deterministic tie-breaker to avoid both peers dialing each other at the same time.
                // This is only for the experiment; production code should use proper connection management.
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
        }
        mdns::Event::Expired(peers) => {
            println!("Expired {} peers", peers.len());
            for (peer, addr) in &peers {
                println!("Expired peer: {:?}, addr: {:?}", peer, addr);
            }
        }
    }
}

fn handle_gossipsub_message(propagation_source: PeerId, message_id: MessageId, message: Message) {
    println!(
        "Got message from: {propagation_source}: '{}', with id: {message_id}",
        String::from_utf8_lossy(&message.data)
    );
}
