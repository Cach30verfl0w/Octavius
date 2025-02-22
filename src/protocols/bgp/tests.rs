use std::io::Cursor;
use crate::protocols::bgp::BGPMessage;
use crate::protocols::bgp::params::OptionalParameter;
use crate::protocols::bgp::rfc3392::Capability;
use crate::protocols::bgp::rfc4760::{AddressFamilyIdentifier, SubsequentAddrFamilyIdentifier};

#[tokio::test]
async fn read_open_message() {
    let mut open_message_binary = Cursor::new(include_bytes!("../../samples/open_message.bin").as_slice());

    // Validate open message
    let BGPMessage::Open(open_message) = BGPMessage::unpack(&mut open_message_binary).await.unwrap() else {
        panic!("Test message isn't an open message");
    };

    assert_eq!(4, open_message.version);
    assert_eq!(65002, open_message.autonomous_system);

    // Validate capabilities
    let OptionalParameter::Capabilities(capabilities) = &open_message.optional_parameters[0] else {
        panic!("First optional parameter isn't a capabilities parameter");
    };

    match &capabilities[0] {
        Capability::MultiprotocolExtensions(extension) => {
            assert_eq!(AddressFamilyIdentifier::IPv4, extension.address_family);
            assert_eq!(SubsequentAddrFamilyIdentifier::Unicast, extension.subsequent_address_family);
        }
        _ => panic!("First capability isn't a multiprotocol extensions capability"),
    }
    match &capabilities[1] {
        Capability::MultiprotocolExtensions(extension) => {
            assert_eq!(AddressFamilyIdentifier::IPv6, extension.address_family);
            assert_eq!(SubsequentAddrFamilyIdentifier::Unicast, extension.subsequent_address_family);
        }
        _ => panic!("First capability isn't a multiprotocol extensions capability"),
    }
}
