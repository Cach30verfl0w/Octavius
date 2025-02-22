# Octavius
**Octavius** is my modern router project implementing BGP (iBGP and eBGP with extensions) in the Rust programming language. This project is massively under work and should currently **not be used in a production environment.**

## ToDo
- [ ] Implement all BGP RFCs planned for implementation
- [ ] Add implementation of OSPF into the router
- [ ] Write incoming routes into the system's routing table
- [ ] Fuzz the protocol implementations for more error-tolerance
- [ ] Test the router implementation against Bird2 in integration tests [with Docker](https://github.com/testcontainers/testcontainers-rs)
