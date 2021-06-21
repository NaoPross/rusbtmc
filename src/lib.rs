/// Rust USB Test and Measurement Class (USBTMC) driver

/* rusbtmc (c) by Nao Pross <np@0hm.ch>
 *
 *
 * rusbtmc is licensed under a
 * Creative Commons Attribution-ShareAlike 4.0 International License.
 *
 * You should have received a copy of the license along with this
 * work. If not, see <http://creativecommons.org/licenses/by-sa/4.0/>.
 */

use rusb;

use std::num::Wrapping;
use std::time::Duration;
use thiserror::Error;

const USBTMC_BINTERFACE_CLASS: u8 = 0xfe;
const USBTMC_BINTERFACE_SUBCLASS: u8 = 3;
// const USBTMC_BINTERFACE_PROTOCOL: u8 = 0;
const USB488_BINTERFACE_PROTOCOL: u8 = 1;

/* control values */

/// USBTMC bRequest Values
#[repr(u8)]
#[allow(dead_code)]
enum RequestType {
    InitiateAbortBulkOut = 1,
    CheckAbortBulkOutStatus = 2,
    InitiateAbortBunkIn = 3,
    CheckAbortBulkInStatus = 4,
    InitiateClear = 5,
    CheckClearStatus = 6,
    GetCapabilities = 7,
    IndicatorPulse = 64,
}

/// USBTMC Status values
#[repr(u8)]
#[allow(dead_code)]
enum Status {
    Success = 0x01,
    Pending = 0x02,
    Failed = 0x80,
    TransferNotInProgress = 0x81,
    SplitNotInProgress = 0x82,
    SplitInProgress = 0x83,
}

/* bulk values */

enum Direction {
    In,
    Out,
}

enum MsgId {
    DeviceDependent,
    VendorSpecific,
}

/* instruments */

/// Capabilities of the USBTMC Devices
#[derive(Clone, Debug)]
pub struct Capabilities {
    /* version number (in BCD) */
    bcd_usbtmc: u16,
    /* interface capabilities */
    /// The device has an indicator for identification purposes
    pub pulse: bool,
    /// The interface is talk-only if it is not capable of processing any Bulk-OUT USBTMC
    /// device dependent message data bytes.
    pub talk_only: bool,
    /// The interface is it is not capable of sending Bulk-IN USBTMC device dependent
    /// message data bytes
    pub listen_only: bool,
    /* device capabilities */
    /// The device supports ending a Bulk-IN transfer from this USBTMC interface when a
    /// byte matches a specified TermChar.
    pub term_char: bool,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("error on low level USB")]
    Rusb(#[from] rusb::Error),
    #[error("device not found")]
    DeviceNotFound,
    #[error("not a usbtmc device")]
    NotUsbtmcDevice,
    #[error("no usb handle")]
    NoHandle,
    #[error("not connected")]
    NotConnected,
    #[error("request failed")]
    Request,
    #[error("device does not support the request type")]
    NotSupported,
    #[error("decoding error (utf-8)")]
    Decoding(#[from] std::string::FromUtf8Error),
    #[error("not implemented")]
    NotImplemented,
}

/// Get a list of connected instruments
pub fn instruments() -> Result<Vec<Instrument<rusb::GlobalContext>>, Error> {
    let devices = match rusb::devices() {
        Ok(devices) => devices,
        Err(e) => return Err(Error::Rusb(e)),
    };

    let mut instruments = Vec::<Instrument<rusb::GlobalContext>>::new();

    for dev in devices.iter() {
        if let Ok(instr) = Instrument::new(dev) {
            instruments.push(instr);
        }
    }

    Ok(instruments)
}

/// 'High level' Instrument wrapper around rusb::Device
pub struct Instrument<C: rusb::UsbContext> {
    connected: bool,
    // rusb objects
    pub device: rusb::Device<C>,
    pub handle: Option<rusb::DeviceHandle<C>>,
    // usbtmc capabilites
    capabilities: Option<Capabilities>,
    // for linux kernel
    has_kernel_driver: bool,
    // addresses in the usb device
    config_num: Option<u8>,
    iface_num: Option<u8>,
    ep_bulk_in: Option<u8>,
    ep_bulk_out: Option<u8>,
    ep_interrupt_in: Option<u8>,
    // btag number to keep track of packet parts
    btag: Wrapping<u8>,
    // default timeout
    timeout: Duration,
}

impl<C: rusb::UsbContext> Instrument<C> {
    /// Creates and Instrument from a rusb Device
    pub fn new(device: rusb::Device<C>) -> Result<Instrument<C>, Error> {
        Ok(Instrument {
            connected: false,
            device: device,
            handle: None,
            capabilities: None,
            has_kernel_driver: false,
            config_num: None,
            iface_num: None,
            ep_bulk_in: None,
            ep_bulk_out: None,
            ep_interrupt_in: None,
            btag: Wrapping(0_u8),
            timeout: Duration::from_millis(20),
        })
    }

    /// Creates an Instrument from the idVendor and idProduct numbers
    pub fn from_vid_pid(
        id_vendor: u16,
        id_product: u16,
    ) -> Result<Instrument<rusb::GlobalContext>, Error> {
        let handle = match rusb::open_device_with_vid_pid(id_vendor, id_product) {
            Some(handle) => handle,
            None => return Err(Error::DeviceNotFound),
        };

        Ok(Instrument {
            connected: false,
            device: handle.device(),
            handle: Some(handle),
            capabilities: None,
            has_kernel_driver: false,
            config_num: None,
            iface_num: None,
            ep_bulk_in: None,
            ep_bulk_out: None,
            ep_interrupt_in: None,
            btag: Wrapping(0_u8),
            timeout: Duration::from_millis(20),
        })
    }

    pub fn is_connected(&self) -> bool {
        return self.connected;
    }

    /// Opens (searches for) the USBTMC interface of the device
    ///
    /// It loops through the available usb interfaces and uses the first that
    /// matches the usbtmc spec class and subclass
    pub fn open(&mut self) -> Result<bool, Error> {
        if self.connected {
            dbg!("device already connected");
            return Ok(self.connected);
        }

        self.handle = match self.device.open() {
            Ok(handle) => Some(handle),
            Err(e) => {
                dbg!("failed to get device handle");
                return Err(Error::Rusb(e));
            }
        };

        let desc = self.device.device_descriptor()?;

        'outer: for cfg_desc in (0..desc.num_configurations())
            .map(|num| self.device.config_descriptor(num))
            .filter_map(|cfg_desc| cfg_desc.ok())
        {
            for iface_desc in cfg_desc
                .interfaces()
                .map(|iface| iface.descriptors())
                .flatten()
            {
                // check if it is an USBTMC device
                if iface_desc.class_code() == USBTMC_BINTERFACE_CLASS
                    && iface_desc.sub_class_code() == USBTMC_BINTERFACE_SUBCLASS
                {
                    // check if it is has USB488
                    if iface_desc.protocol_code() == USB488_BINTERFACE_PROTOCOL {
                        // TODO
                        return Err(Error::NotImplemented);
                    }

                    self.config_num = Some(cfg_desc.number());
                    self.iface_num = Some(iface_desc.interface_number());

                    // find endpoints
                    for ep_desc in iface_desc.endpoint_descriptors() {
                        match ep_desc.transfer_type() {
                            rusb::TransferType::Bulk => match ep_desc.direction() {
                                rusb::Direction::Out => {
                                    self.ep_bulk_out = Some(ep_desc.address());
                                }
                                rusb::Direction::In => {
                                    self.ep_bulk_in = Some(ep_desc.address());
                                }
                            },
                            rusb::TransferType::Interrupt => {
                                if ep_desc.direction() == rusb::Direction::In {
                                    self.ep_interrupt_in = Some(ep_desc.address());
                                }
                            }
                            // not interested in other cases
                            _ => {}
                        }
                    }

                    // found first interface = happy
                    break 'outer;
                }
            }
        }

        // check for valid addresse
        if self.ep_bulk_out.is_none() || self.ep_bulk_in.is_none() || self.ep_interrupt_in.is_none()
        {
            return Err(Error::NotUsbtmcDevice);
        }

        let handle = self.handle.as_mut().unwrap(); // is this safe?

        // detach kernel driver if necessary
        let iface_num = match self.iface_num {
            Some(num) => num,
            None => {
                dbg!("no interface number");
                return Err(Error::NotUsbtmcDevice);
            }
        };
        self.has_kernel_driver = match handle.kernel_driver_active(iface_num) {
            Ok(true) => {
                if let Err(e) = handle.detach_kernel_driver(iface_num) {
                    dbg!("failed to detach kernel driver");
                    return Err(Error::Rusb(e));
                }
                true
            }
            _ => false,
        };

        // set configuration if not correct
        let config_num = match self.config_num {
            Some(num) => num,
            None => {
                dbg!("no configuration number");
                return Err(Error::NotUsbtmcDevice);
            }
        };

        let active_conf = handle.active_configuration();
        if active_conf != Ok(config_num) {
            if let Err(e) = handle.set_active_configuration(config_num) {
                dbg!("failed to set configuration");
                return Err(Error::Rusb(e));
            }
            dbg!(format!("set configuration to {}", config_num));
        }

        // claim the interface
        if let Err(e) = handle.claim_interface(iface_num) {
            dbg!("failed to claim interface");
            return Err(Error::Rusb(e));
        }

        self.connected = true;

        if let Err(e) = self.clear() {
            return Err(e);
        }

        Ok(self.connected)
    }

    /// Closes the devices
    pub fn close(&mut self) {
        if !self.connected {
            return;
        }

        if let Some(handle) = &mut self.handle {
            if let Some(iface_num) = self.iface_num {
                if let Err(e) = handle.release_interface(iface_num) {
                    dbg!(e);
                    dbg!("failed to release interface");
                }

                if self.has_kernel_driver {
                    if let Err(e) = handle.attach_kernel_driver(iface_num) {
                        dbg!(e);
                        dbg!("failed to attach kernel driver");
                    }
                }
            }
        }

        // TODO: reset configuration

        self.connected = false;

        self.ep_bulk_out = None;
        self.ep_bulk_in = None;
        self.ep_interrupt_in = None;
    }

    /// Sends a clear request and waits for it to complete
    pub fn clear(&mut self) -> Result<(), Error> {
        if !self.connected {
            return Err(Error::NotConnected);
        }

        let handle = self.handle.as_mut().unwrap();
        let index = self.iface_num.unwrap();

        // response buffer
        let buf: &mut [u8] = &mut [0];

        // send clear request
        if let Err(e) = handle.read_control(
            rusb::request_type(
                rusb::Direction::In,
                rusb::RequestType::Class,
                rusb::Recipient::Interface,
            ),
            RequestType::InitiateClear as u8,
            0x0000,
            index.into(),
            buf,
            self.timeout,
        ) {
            dbg!("failed to send clear request");
            return Err(Error::Rusb(e));
        }

        if buf[0] != Status::Success as u8 {
            return Err(Error::Request);
        }

        // wait for completion of clear
        loop {
            // response buffer
            let mut buf: &mut [u8] = &mut [0, 0];

            // send check status
            if let Err(e) = handle.read_control(
                rusb::request_type(
                    rusb::Direction::In,
                    rusb::RequestType::Class,
                    rusb::Recipient::Interface,
                ),
                RequestType::CheckClearStatus as u8,
                0x0000,
                index.into(),
                &mut buf,
                self.timeout,
            ) {
                return Err(Error::Rusb(e));
            }

            if buf[0] != Status::Pending as u8 {
                break;
            }

            std::thread::sleep(Duration::from_millis(100));
        }

        // clear halt condition
        let bulk_out_ep = self.ep_bulk_out.unwrap();
        if let Err(e) = handle.clear_halt(bulk_out_ep) {
            dbg!("failed to clear halt");
            return Err(Error::Rusb(e));
        }

        Ok(())
    }

    /// Ask to the device with features are supported
    pub fn get_capabilities(&mut self) -> Result<Capabilities, Error> {
        if !self.connected {
            return Err(Error::NotConnected);
        }

        let handle = self.handle.as_mut().unwrap();
        let index = self.iface_num.unwrap();

        // response buffer
        let buf: &mut [u8; 0x18] = &mut [0; 0x18];

        // send request
        if let Err(e) = handle.read_control(
            rusb::request_type(
                rusb::Direction::In,
                rusb::RequestType::Class,
                rusb::Recipient::Interface,
            ),
            RequestType::GetCapabilities as u8,
            0x0000,
            index.into(),
            buf,
            self.timeout,
        ) {
            dbg!("failed to send get capabilities request");
            return Err(Error::Rusb(e));
        }

        if buf[0] != Status::Success as u8 {
            return Err(Error::Request);
        }

        // TODO: USB448 subclass

        let bcd_usbtmc: u16 = (u16::from(buf[3]) << 8) + u16::from(buf[2]);
        let capabilities = Capabilities {
            bcd_usbtmc: bcd_usbtmc,
            pulse: (buf[4] & 4) != 0,
            talk_only: (buf[4] & 2) != 0,
            listen_only: (buf[4] & 1) != 0,
            term_char: (buf[5] & 1) != 0,
        };

        self.capabilities = Some(capabilities.clone());
        Ok(capabilities)
    }

    ///
    pub fn pulse(&mut self) -> Result<(), Error> {
        if !self.connected {
            return Err(Error::NotConnected);
        }

        let can_pulse = match &self.capabilities {
            Some(c) => c.pulse,
            None => {
                let c = self.get_capabilities()?;
                c.pulse
            }
        };

        if !can_pulse {
            return Err(Error::NotSupported);
        }

        let handle = self.handle.as_ref().unwrap();
        let index = self.iface_num.unwrap();

        let buf: &mut [u8] = &mut [0];

        // send request
        if let Err(_) = handle.read_control(
            rusb::request_type(
                rusb::Direction::In,
                rusb::RequestType::Class,
                rusb::Recipient::Interface,
            ),
            RequestType::GetCapabilities as u8,
            0x0000,
            index.into(),
            buf,
            self.timeout,
        ) {
            return Err(Error::NotSupported);
        }

        Ok(())
    }

    /// Write a string to the instrument
    pub fn write(&mut self, message: &str) -> Result<usize, Error> {
        return self.write_raw(message.as_bytes());
    }

    /// Write binary data to the instrument
    pub fn write_raw(&mut self, data: &[u8]) -> Result<usize, Error> {
        if !self.connected {
            return Err(Error::NotConnected);
        }

        let mut sent_bytes = 0;

        let handle = self.handle.as_ref().unwrap();
        let endpoint = self.ep_bulk_out.unwrap();

        const HEADER_SIZE: usize = 12;
        const TRANSFER_SIZE: usize = 1024 * 1024;
        const PACKET_SIZE: usize = HEADER_SIZE + TRANSFER_SIZE;

        // reset btag counter
        self.btag = Wrapping(1_u8);

        // send chunks
        let iter = data.chunks_exact(TRANSFER_SIZE);
        let last_data = iter.remainder();

        for chunk in iter {
            let header = make_bulk_header(
                MsgId::DeviceDependent,
                Direction::Out,
                self.btag.0,
                TRANSFER_SIZE as u32,
                false,
            );

            let mut packet: [u8; PACKET_SIZE] = [0; PACKET_SIZE];
            packet[..HEADER_SIZE].clone_from_slice(&header);
            packet[(HEADER_SIZE +1)..].clone_from_slice(chunk);

            sent_bytes += match handle.write_bulk(endpoint, &packet, self.timeout) {
                Ok(sent) => sent,
                Err(e) => {
                    dbg!("failed to send chunk during bulk out");
                    self.abort_bulk_out()?;
                    return Err(Error::Rusb(e));
                }
            };

            // increment btag
            if self.btag.0 == 0 {
                self.btag = Wrapping(1_u8);
            } else {
                self.btag += Wrapping(1_u8);
            }
        }

        // send remainder
        let pad_size = (4 - (last_data.len() % 4)) % 4;
        let last_data_size: usize = last_data.len() + pad_size;

        let header = make_bulk_header(
            MsgId::DeviceDependent,
            Direction::Out,
            self.btag.0,
            last_data_size as u32,
            true,
        );

        let mut packet: [u8; PACKET_SIZE] = [0; PACKET_SIZE];
        packet[..HEADER_SIZE].clone_from_slice(&header);
        for i in 0..last_data.len() {
            packet[HEADER_SIZE + 1 + i] = last_data[i];
        }

        sent_bytes += match handle.write_bulk(
            endpoint,
            &packet[..(HEADER_SIZE + last_data_size)],
            self.timeout
        ) {
            Ok(sent) => sent,
            Err(e) => {
                dbg!("failed to send chunk during bulk out");
                self.abort_bulk_out()?;
                return Err(Error::Rusb(e));
            }
        };

        Ok(sent_bytes)
    }

    /// Abort a bulk-out operation
    fn abort_bulk_out(&mut self) -> Result<(), Error> {
        if !self.connected {
            return Err(Error::NotConnected);
        }

        let handle = self.handle.as_ref().unwrap();
        let endpoint = self.ep_bulk_out.unwrap();

        let buf: &[u8; 2] = &[0, 0];
        if let Err(e) = handle.write_control(
            rusb::request_type(
                rusb::Direction::In,
                rusb::RequestType::Class,
                rusb::Recipient::Endpoint,
            ),
            RequestType::InitiateAbortBulkOut as u8,
            u16::from(self.btag.0),
            endpoint.into(),
            buf,
            self.timeout,
        ) {
            dbg!("failed to initiate abort bulk out");
            return Err(Error::Rusb(e));
        }

        Ok(())
    }

    /// Read binary data from the device and decode into an utf-8 string
    pub fn read(&mut self) -> Result<String, Error> {
        let data = self.read_raw()?;
        return match String::from_utf8(data) {
            Ok(s) => Ok(s),
            Err(e) => Err(Error::Decoding(e)),
        };
    }

    /// Read binary data from the device
    pub fn read_raw(&mut self) -> Result<Vec<u8>, Error> {
        return Err(Error::NotImplemented);
    }
}

/// helper function to create bulk headers
fn make_bulk_header(
    msgid: MsgId,
    direction: Direction,
    btag: u8,
    transfer_size: u32,
    is_last: bool,
) -> [u8; 12] {
    // table 2 in spec
    let msgid_nr: u8 = match msgid {
        MsgId::DeviceDependent => match direction {
            Direction::Out => 1,
            Direction::In => 2,
        },
        MsgId::VendorSpecific => match direction {
            Direction::Out => 126,
            Direction::In => 127,
        },
    };

    let ts_bytes = transfer_size.to_le_bytes();
    let header: [u8; 12] = [
        // table 1 in spec
        msgid_nr,
        btag,
        !btag,
        0x00,
        // table 3 in spec
        // size of the transfer, without header
        ts_bytes[0],
        ts_bytes[1],
        ts_bytes[2],
        ts_bytes[3],
        // whether this is the last chunk
        match is_last {
            true => 0x01,
            false => 0x00,
        },
        // reserved, must be zeroes
        0x00,
        0x00,
        0x00,
    ];

    header
}

impl<C: rusb::UsbContext> std::fmt::Debug for Instrument<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // TODO: complete
        f.debug_struct("Instrument")
            .field("connected", &self.connected)
            .field("capabilities", &self.capabilities)
            .field("has_kernel_driver", &self.has_kernel_driver)
            .field("config_num", &self.config_num)
            .field("iface_num", &self.iface_num)
            .finish()

    }
}

