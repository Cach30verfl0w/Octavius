mod multiprotocol_extensions {
    use crate::{
        prefix::{
            AddressFamily,
            Prefix,
        },
        rfc3392::Capability::MultiprotocolExtensions,
        rfc4271::{
            OptionalParameter,
            PathAttribute,
        },
        rfc4760::{
            MultiprotocolExtensionsCapability,
            MultiprotocolReachNLRI,
            SubsequentAddressFamily,
        },
        BGPElement,
        BGPMessage,
        NextHop,
    };
    use core::str::FromStr;
    use std::{
        net::{
            IpAddr,
            Ipv6Addr,
        },
        vec,
    };

    #[test]
    fn test_open_message() {
        let BGPMessage::Open(open_message) = BGPMessage::unpack(include_bytes!("../test_data/0/packet_1.bin")).unwrap().1 else {
            panic!("Message is not an open message");
        };
        let OptionalParameter::Capabilities(capabilities) = open_message.optional_parameters.get(0).unwrap() else {
            panic!("First optional parameter isn't capabilities info");
        };

        assert_eq!(
            capabilities[0],
            MultiprotocolExtensions(MultiprotocolExtensionsCapability {
                address_family: AddressFamily::IPv4,
                subsequent_address_family: SubsequentAddressFamily::Unicast
            })
        );
        assert_eq!(
            capabilities[1],
            MultiprotocolExtensions(MultiprotocolExtensionsCapability {
                address_family: AddressFamily::IPv6,
                subsequent_address_family: SubsequentAddressFamily::Unicast
            })
        );
    }

    #[test]
    fn test_update_message() {
        let messages = BGPMessage::unpack_many(include_bytes!("../test_data/0/packet_7.bin")).unwrap().1;
        let BGPMessage::Update(update_message) = messages.get(1).unwrap() else {
            panic!("Message is not an update message");
        };
        let PathAttribute::MpReachNlri(nlri) = update_message.path_attributes.get(0).unwrap() else {
            panic!("First path attribute isn't a MP NLRI");
        };

        assert_eq!(
            *nlri,
            MultiprotocolReachNLRI {
                address_family: AddressFamily::IPv6,
                subsequent_address_family: SubsequentAddressFamily::Unicast,
                next_hop: NextHop {
                    next_hop: IpAddr::V6(Ipv6Addr::from_str("2003:de:6f44:c9bf:9414:9acf:1cc9:8ff9").unwrap()),
                    link_local_address: Some(IpAddr::V6(Ipv6Addr::from_str("fe80::56e8:fd91:6c8e:a350").unwrap())),
                },
                nlri: vec![
                    Prefix::from_str("fdb3:3458:e9b1:eab9::/64").unwrap(),
                    Prefix::from_str("fd8b:c81d:be40:87f0::/64").unwrap()
                ],
            }
        )
    }
}
