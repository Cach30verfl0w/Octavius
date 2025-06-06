# Octavius
**Octavius** is my modern router project implementing BGP (iBGP and eBGP with extensions) in the Rust programming language. This project is massively under work and should currently **not be used in a production environment.**

## ToDo
- [ ] Implement all BGP RFCs planned for implementation
- [ ] Add implementation of OSPF into the router
- [ ] Write incoming routes into the system's routing table
- [ ] Fuzz the protocol implementations for more error-tolerance ([ref](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html))
- [ ] Test the router implementation against Bird2 in integration tests [with Docker](https://github.com/testcontainers/testcontainers-rs)
- [ ] Extract the protocol implementations as separate crates (and more documentation)
- [ ] Limit extension support with features which can be set at compilation