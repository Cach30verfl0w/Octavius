use std::str::FromStr;
use crate::prefix::Prefix;
use crate::protocols::bgp::{BGPMessage, PathAttribute};
use crate::protocols::bgp::params::OptionalParameter;
use crate::protocols::bgp::rfc3392::Capability;
use crate::protocols::bgp::path_attr::Origin;
use crate::protocols::bgp::rfc4760::{AddressFamily, SubsequentAddressFamily};

#[test]
fn read_open_message() {
    let open_message_binary = include_bytes!("test-files/open_message.bin").as_slice();

    // Validate open message
    let BGPMessage::Open(open_message) = BGPMessage::unpack(&open_message_binary).unwrap().1 else {
        panic!("Test message isn't an open message");
    };

    println!("{:#?}", open_message);
    assert_eq!(4, open_message.version);
    assert_eq!(65002, open_message.autonomous_system);

    // Validate capabilities
    let OptionalParameter::Capabilities(capabilities) = &open_message.optional_parameters[0] else {
        panic!("First optional parameter isn't a capabilities parameter");
    };

    match &capabilities[0] {
        Capability::MultiprotocolExtensions(extension) => {
            assert_eq!(AddressFamily::IPv4, extension.address_family);
            assert_eq!(SubsequentAddressFamily::Unicast, extension.subsequent_address_family);
        }
        _ => panic!("First capability isn't a multiprotocol extensions capability"),
    }
    match &capabilities[1] {
        Capability::MultiprotocolExtensions(extension) => {
            assert_eq!(AddressFamily::IPv6, extension.address_family);
            assert_eq!(SubsequentAddressFamily::Unicast, extension.subsequent_address_family);
        }
        _ => panic!("First capability isn't a multiprotocol extensions capability"),
    }
}

#[test]
fn read_update_message_1() {
    let mut update_message_binary = include_bytes!("test-files/update_message_0.bin").as_slice();
    let BGPMessage::Update(update_message) = BGPMessage::unpack(&mut update_message_binary).unwrap().1 else {
        panic!("Test message isn't an update message");
    };

    println!("{:#?}", update_message);
    let path_attributes = &update_message.path_attributes;
    assert_eq!(PathAttribute::Origin(Origin::IGP), path_attributes[0]);

    let prefixes = &update_message.network_layer_reachability_information;
    assert_eq!(Prefix::from_str("192.168.100.0/24").unwrap(), prefixes[0]);
}

#[test]
fn read_update_message_2() {
    let mut update_message_binary = include_bytes!("test-files/update_message_2.bin").as_slice();
    let messages = BGPMessage::unpack_many(&mut update_message_binary).unwrap().1;
    println!("{:#?}", messages);
}


#[test]
fn read_update_message_3() {
    let mut update_message_binary = include_bytes!("test-files/update_message_3.bin").as_slice();
    let messages = BGPMessage::unpack_many(&mut update_message_binary).unwrap().1;
    println!("{:#?}", messages);
}
