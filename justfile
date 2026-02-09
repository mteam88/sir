set shell := ["zsh", "-cu"]

build:
    cargo build

test:
    cargo test

clippy:
    cargo clippy --all-targets --all-features -- -D warnings

fmt:
    cargo fmt

run *args:
    cargo run -- {{args}}
