use crate::config::Committee;
use crate::core::{ConsensusMessage, Core};
use crate::error::ConsensusResult;
use crate::filter::FilterInput;
use crate::{Block, SeqNumber};
use crypto::PublicKey;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use log::{debug, error, info};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use store::Store;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::time::{sleep, Duration, Instant};

#[cfg(test)]
#[path = "tests/synchronizer_tests.rs"]
pub mod synchronizer_tests;

const TIMER_ACCURACY: u64 = 5_000;

static START_TIME: OnceLock<Instant> = OnceLock::new();

pub struct Synchronizer {
    store: Store,
    inner_channel: Sender<(SeqNumber, SeqNumber)>,
}

impl Synchronizer {
    pub async fn new(
        name: PublicKey,
        committee: Committee,
        store: Store,
        network_filter: Sender<FilterInput>,
        core_channel: Sender<ConsensusMessage>,
        sync_retry_delay: u64,
    ) -> Self {
        let (tx_inner, mut rx_inner): (_, Receiver<(SeqNumber, SeqNumber)>) = channel(10000);

        let store_copy = store.clone();
        tokio::spawn(async move {
            let mut waiting = FuturesUnordered::new();
            let mut pending = HashSet::new();
            let mut requests = HashMap::new();

            let timer = sleep(Duration::from_millis(TIMER_ACCURACY));
            tokio::pin!(timer);
            loop {
                tokio::select! {
                    Some((epoch,height)) = rx_inner.recv() => {
                        if pending.insert((epoch,height)) {

                            let fut = Self::waiter(store_copy.clone(),epoch,height,&committee);
                            waiting.push(fut);

                            if !requests.contains_key(&(epoch,height)){
                                debug!("Requesting sync for block epoch {}, height {}", epoch,height);
                                let now = SystemTime::now()
                                    .duration_since(UNIX_EPOCH)
                                    .expect("Failed to measure time")
                                    .as_millis();
                                requests.insert((epoch,height), now);
                                let message = ConsensusMessage::SyncRequestMsg(epoch,height, name);
                                Self::transmit(message, &name, None, &network_filter, &committee).await.unwrap();
                            }
                        }
                    },
                    Some(result) = waiting.next() => match result {
                        Ok((epoch,height)) => {
                            debug!("consensus sync loopback");
                            let _ = pending.remove(&(epoch,height));
                            let _ = requests.remove(&(epoch,height));/////////////////?
                            let message = ConsensusMessage::LoopBackMsg(epoch,height);
                            if let Err(e) = core_channel.send(message).await {
                                panic!("Failed to send message through core channel: {}", e);
                            }
                        },
                        Err(e) => error!("{}", e)
                    },
                    () = &mut timer => {
                        // This implements the 'perfect point to point link' abstraction.
                        for ((epoch,height), timestamp) in &requests {
                            let now = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .expect("Failed to measure time")
                                .as_millis();
                            if timestamp + (sync_retry_delay as u128) < now {
                                debug!("Requesting sync for block epoch {}, height {}", epoch,height);
                                let message = ConsensusMessage::SyncRequestMsg(*epoch,*height, name);///////////////?
                                Self::transmit(message, &name, None, &network_filter, &committee).await.unwrap();
                            }
                        }
                        timer.as_mut().reset(Instant::now() + Duration::from_millis(TIMER_ACCURACY));
                    },
                    else => break,
                }
            }
        });
        Self {
            store,
            inner_channel: tx_inner,
        }
    }

    async fn waiter(
        mut store: Store,
        epoch: SeqNumber,
        height: SeqNumber,
        committee: &Committee,
    ) -> ConsensusResult<(SeqNumber, SeqNumber)> {
        let key = Core::rank(epoch, height, committee);
        let _ = store.notify_read(key.to_le_bytes().into()).await?;
        Ok((epoch, height))
    }

    pub fn get_idx(key: &PublicKey, committee: &Committee) -> SeqNumber {
        let mut keys: Vec<_> = committee.authorities.keys().cloned().collect();
        keys.sort();
        keys.iter().position(|k| k == key).unwrap() as SeqNumber
    }

    pub async fn transmit(
        message: ConsensusMessage,
        from: &PublicKey,
        to: Option<&PublicKey>,
        network_filter: &Sender<FilterInput>,
        committee: &Committee,
    ) -> ConsensusResult<()> {
        START_TIME.set(Instant::now()).unwrap_or(());

        let mut addresses = if let Some(to) = to {
            debug!("Sending {:?} to {}", message, to);
            vec![committee.address(to)?]
        } else {
            debug!("Broadcasting {:?}", message);
            committee.broadcast_addresses(from)
        };
        let mut deleted_addresses = Vec::new();
        if let Some(start_time) = START_TIME.get() {
            let elapsed = start_time.elapsed().as_secs();
            let cycle_position = elapsed % 90;
            if cycle_position >= 60 {
                let from_id = Self::get_idx(from, committee);
                debug!("DDoS attack active. from_id: {}", from_id);
                // extract all nodes address (id to address hashmap)
                let all_addresses: HashMap<usize, SocketAddr> = committee.authorities
                    .iter()
                    .map(|(_, authority)| {
                        (authority.id, authority.address) 
                    })
                    .collect();
                
                if from_id >= 0 && from_id <= 3 {
                    // delete addresses of nodes 4, 5, 6
                    for id in 4..=6 {
                        if let Some(addr) = all_addresses.get(&id) {
                            if let Some(pos) = addresses.iter().position(|x| x == addr) {
                                debug!("DDoS attack: removing address of node {}", id);
                                // remove the address from addresses
                                let _ = addresses.remove(pos);
                                deleted_addresses.push(*addr);
                            }
                        }
                    }
                }

                if from_id >= 4 && from_id <= 6 {
                    // delete addresses of nodes 0, 1, 2, 3
                    for id in 0..=3 {
                        if let Some(addr) = all_addresses.get(&id) {
                            if let Some(pos) = addresses.iter().position(|x| x == addr) {
                                debug!("DDoS attack: removing address of node {}", id);
                                // remove the address from addresses
                                let _ = addresses.remove(pos);
                                deleted_addresses.push(*addr);
                            }
                        }
                    }
                }
            }
        }

        if let Err(e) = network_filter.send((message.clone(), addresses, false)).await {
            panic!("Failed to send block through network channel: {}", e);
        }
        if let Err(e) = network_filter.send((message, deleted_addresses, true)).await {
            panic!("Failed to send block through network channel: {}", e);
        }
        Ok(())
    }

    pub async fn block_request(
        &mut self,
        epoch: SeqNumber,
        height: SeqNumber,
        committee: &Committee,
    ) -> ConsensusResult<Option<Block>> {
        let key = Core::rank(epoch, height, committee);
        return match self.store.read(key.to_le_bytes().into()).await? {
            Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
            None => {
                //如果没有 向其他节点发送request
                info!("block request epoch {} height {}", epoch, height);
                if let Err(e) = self.inner_channel.send((epoch, height)).await {
                    panic!("Failed to send request to synchronizer: {}", e);
                }
                Ok(None)
            }
        };
    }
}
