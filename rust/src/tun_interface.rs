//! Virtual network device that bridges smoltcp with boringtun.
//!
//! Instead of talking to real hardware or a TUN device, this `Device`
//! implementation exchanges raw IP packets via in-memory queues.
//! Outgoing packets are encrypted by boringtun and sent over UDP.
//! Incoming packets arrive from UDP, are decrypted by boringtun,
//! and injected into the receive queue for smoltcp to process.

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::collections::VecDeque;

/// A virtual network device that shuttles raw IP packets between
/// smoltcp and the WireGuard encryption layer.
pub struct VirtualDevice {
    /// Packets received from the WireGuard peer (decrypted), ready for smoltcp.
    rx_queue: VecDeque<Vec<u8>>,
    /// Packets transmitted by smoltcp, to be encrypted and sent via WireGuard.
    tx_queue: VecDeque<Vec<u8>>,
    /// Maximum Transmission Unit.
    mtu: usize,
}

impl VirtualDevice {
    pub fn new(mtu: u16) -> Self {
        VirtualDevice {
            rx_queue: VecDeque::with_capacity(64),
            tx_queue: VecDeque::with_capacity(64),
            mtu: mtu as usize,
        }
    }

    /// Inject a decrypted IP packet (from boringtun) into the receive queue.
    /// smoltcp will pick it up on the next poll.
    pub fn inject_rx(&mut self, packet: Vec<u8>) {
        self.rx_queue.push_back(packet);
    }

    /// Drain all packets that smoltcp wants to transmit.
    /// These need to be encrypted by boringtun and sent over UDP.
    pub fn drain_tx(&mut self) -> impl Iterator<Item = Vec<u8>> + '_ {
        self.tx_queue.drain(..)
    }

    /// Check if there are packets waiting to be transmitted.
    pub fn has_tx(&self) -> bool {
        !self.tx_queue.is_empty()
    }

    /// Check if there are packets waiting to be received.
    pub fn has_rx(&self) -> bool {
        !self.rx_queue.is_empty()
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(packet) = self.rx_queue.pop_front() {
            Some((
                VirtualRxToken { buffer: packet },
                VirtualTxToken {
                    queue: &mut self.tx_queue,
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(VirtualTxToken {
            queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// Token for receiving a single packet from the virtual device.
pub struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = self.buffer;
        f(&mut buffer)
    }
}

/// Token for transmitting a single packet through the virtual device.
pub struct VirtualTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}
