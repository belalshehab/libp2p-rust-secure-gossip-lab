use base64::{Engine as _, engine::general_purpose::STANDARD};
use libp2p::gossipsub::{Message, MessageId};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::{
    PeerId, Swarm, SwarmBuilder, gossipsub,
    identity::Keypair,
    mdns,
    swarm::{NetworkBehaviour, SwarmEvent},
};

use crate::error::AppError;
use crate::message::SignedChatMessage;
use crate::validator::Validator;

pub mod error;
pub mod identity;
pub mod message;
pub mod validator;

#[derive(NetworkBehaviour)]
pub struct SecureGossipBehaviour {
    pub mdns: Toggle<mdns::tokio::Behaviour>,
    pub gossipsub: gossipsub::Behaviour,
}

pub fn build_swarm(
    local_key: Keypair,
    no_mdns: bool,
) -> Result<(Swarm<SecureGossipBehaviour>, gossipsub::IdentTopic), AppError> {
    let local_peer_id = PeerId::from(local_key.public());

    let config = gossipsub::ConfigBuilder::default()
        .validate_messages()
        .build()
        .expect("valid gossipsub config");

    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        config,
    )
    .map_err(|e| AppError::Libp2p(e.to_string()))?;

    let topic = gossipsub::IdentTopic::new("secure-gossip-lab/v1/chat");
    gossipsub
        .subscribe(&topic)
        .map_err(|e| AppError::Libp2p(e.to_string()))?;

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
        )
        .map_err(|e| AppError::Libp2p(e.to_string()))?
        .with_behaviour(|_| behaviour)
        .map_err(|e| AppError::Libp2p(e.to_string()))?
        .build();
    Ok((swarm, topic))
}

pub fn handle_event(
    event: SwarmEvent<SecureGossipBehaviourEvent>,
    swarm: &mut Swarm<SecureGossipBehaviour>,
    local_peer_id: &PeerId,
    validator: &Validator,
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
            let acceptance =
                handle_gossipsub_message(&propagation_source, &message_id, message, validator);
            if !swarm
                .behaviour_mut()
                .gossipsub
                .report_message_validation_result(&message_id, &propagation_source, acceptance)
            {
                eprintln!("Failed to report message validation result: message_id not found");
            }
        }

        event => {
            println!("Swarm event: {event:?}");
        }
    }
}

fn handle_mdns(
    event: mdns::Event,
    swarm: &mut Swarm<SecureGossipBehaviour>,
    local_peer_id: &PeerId,
) {
    match event {
        mdns::Event::Discovered(peers) => {
            println!("Discovered {} new peers", peers.len());
            for (peer, addr) in peers {
                if peer == *local_peer_id {
                    continue;
                }
                println!("Discovered peer: {:?}, addr: {:?}", peer, addr);
                // Deterministic tie-breaker to avoid both peers dialing each other at the same time.
                // This is only for the experiment; production code should use proper connection management.
                let should_dial = local_peer_id.to_string() < peer.to_string();
                if should_dial {
                    println!("Dialing discovered peer.");
                    if let Err(err) = swarm.dial(addr.clone()) {
                        eprintln!("Failed to dial discovered peer {peer}: {err}");
                    }
                } else {
                    println!("Waiting for discovered peer to dial us.");
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

fn handle_gossipsub_message(
    propagation_source: &PeerId,
    message_id: &MessageId,
    message: Message,
    validator: &Validator,
) -> gossipsub::MessageAcceptance {
    match serde_json::from_slice::<SignedChatMessage>(&message.data) {
        Ok(msg) => {
            if msg.signature.is_empty() {
                eprintln!(
                    "REJECTED message from '{}': unsigned messages not allowed",
                    msg.sender_id
                );
                gossipsub::MessageAcceptance::Reject
            } else {
                let sig_bytes = STANDARD.decode(&msg.signature);
                let payload = crate::message::signing_payload(&msg.sender_id, &msg.payload);
                match sig_bytes {
                    Err(_) => {
                        eprintln!(
                            "REJECTED message from '{}': malformed signature",
                            msg.sender_id
                        );
                        gossipsub::MessageAcceptance::Reject
                    }
                    Ok(sig_bytes) => {
                        match validator.validate_signature(&msg.sender_id, &payload, &sig_bytes) {
                            Ok(()) => {
                                println!(
                                    "From: {} (verified ✓): [{}] '{}'",
                                    msg.sender_id, message_id, msg.payload
                                );
                                gossipsub::MessageAcceptance::Accept
                            }
                            Err(reason) => {
                                eprintln!("REJECTED message from '{}': {}", msg.sender_id, reason);
                                gossipsub::MessageAcceptance::Reject
                            }
                        }
                    }
                }
            }
        }
        Err(_) => {
            println!("From {propagation_source}: [non-envelope message, ignoring]");
            gossipsub::MessageAcceptance::Ignore
        }
    }
}
