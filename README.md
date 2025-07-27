# Record-Set-Go: a Domain Connect DNS provider implementation in Rust

## Features

- Connects to DNS servers that can process TSIG-authenticated updates
- Single binary with no external dependencies
- Uses templates for the HTML preview page

## Limitations

- Currently only supports TSIG authentication (HMAC-SHA256 only) for DNS updates
- Unauthenticated sync flow only, no OAuth flow for now
- Currently only connects to a single DNS server
- Currently only supports A and TXT records (more soon)

## Getting started

1. Install a stable Rust toolchain and clone the repository. Make sure a recent
   version of the hickory-dns server is installed, like with
   `cargo install --git https://github.com/hickory-dns/hickory-dns hickory-dns`.
2. `cd demo` and execute `./run.sh` to start the DNS server (listening on port 53)
3. Use `dig example.com @localhost` to verify the DNS server is running
   but no A records for the apex domain exist yet.
4. Run `cargo run -- --config demo/config.toml` to start the server
   (Consider using `RUST_LOG=record_set_go=debug` to enable debug logging.)
5. Open your browser and navigate to:

   http://localhost:8000/v2/domainTemplates/providers/exampleservice.domainconnect.org/services/template1/apply?domain=example.com&IP=10.10.10.1&RANDOMTEXT=foobar

6. Click the `Apply` button to apply the template.
7. Use `dig example.com @localhost` to verify the A record has been created.
8. Use `dig example.com TXT @localhost` to verify the TXT record has been created.
