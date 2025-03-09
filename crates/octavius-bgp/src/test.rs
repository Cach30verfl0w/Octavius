mod base {
    use crate::{
        prefix::Prefix,
        rfc4271::{
            ASPathSegment,
            Origin,
            PathAttribute,
        },
        BGPElement,
        BGPMessage,
        NextHop,
    };
    use core::str::FromStr;
    use std::{
        net::IpAddr,
        vec,
    };

    #[test]
    fn test_update_message() {
        let BGPMessage::Update(update_message) = BGPMessage::unpack(include_bytes!("../test_data/0/packet_6.bin")).unwrap().1 else {
            panic!("Message is not an update message");
        };

        let path_attributes = &update_message.path_attributes;
        assert_eq!(path_attributes[0], PathAttribute::Origin(Origin::IGP));
        assert_eq!(path_attributes[1], PathAttribute::AsPath(ASPathSegment::Sequence(vec![65002])));
        assert_eq!(
            path_attributes[2],
            PathAttribute::NextHop(NextHop {
                next_hop: IpAddr::from_str("192.168.2.200").unwrap(),
                link_local_address: None
            })
        );

        let nlri = &update_message.nlri;
        assert_eq!(nlri[0], Prefix::from_str("192.168.100.0/24").unwrap());
    }
}

mod communities {
    use crate::{
        rfc1997::{
            Assignment,
            Community,
            CommunityFlags,
        },
        rfc4271::PathAttribute,
        BGPMessage,
    };
    use std::vec;

    #[test]
    fn test_update_message_with_communities() {
        let messages = BGPMessage::unpack_many(include_bytes!("../test_data/2/packet_7.bin")).unwrap().1;
        let BGPMessage::Update(update_message) = messages.get(1).unwrap() else {
            panic!("Message is not an update message");
        };

        let path_attributes = &update_message.path_attributes;
        assert_eq!(
            path_attributes[3],
            PathAttribute::Communities(vec![
                Community::RFC1997 {
                    global_administrator: 65001,
                    local_administrator: 1
                },
                Community::RFC1997 {
                    global_administrator: 65535,
                    local_administrator: 65281
                }
            ])
        );
    }

    #[test]
    fn test_update_message_with_extended_communities() {
        let messages = BGPMessage::unpack_many(include_bytes!("../test_data/2/packet_7.bin")).unwrap().1;
        let BGPMessage::Update(update_message) = messages.get(1).unwrap() else {
            panic!("Message is not an update message");
        };

        let path_attributes = &update_message.path_attributes;
        assert_eq!(
            path_attributes[4],
            PathAttribute::ExtendedCommunities(vec![Community::RFC4360ASN {
                subkind: Assignment::RouteTarget,
                flags: CommunityFlags::empty(),
                global_administrator: 65001,
                local_administrator: 200
            }])
        );
    }
}

mod multiprotocol_extensions {
    use crate::{
        prefix::{
            AddressFamily,
            Prefix,
        },
        rfc3392::Capability,
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
            Capability::MultiprotocolExtensions(MultiprotocolExtensionsCapability {
                address_family: AddressFamily::IPv4,
                subsequent_address_family: SubsequentAddressFamily::Unicast
            })
        );
        assert_eq!(
            capabilities[1],
            Capability::MultiprotocolExtensions(MultiprotocolExtensionsCapability {
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

        let path_attributes = &update_message.path_attributes;
        assert_eq!(
            path_attributes[0],
            PathAttribute::MpReachNlri(MultiprotocolReachNLRI {
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
            })
        )
    }
}
