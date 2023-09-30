# protonkt-monitor

Monitor Proton's Key Transparency. It monitors:

- for equivocation, by searching CT for all tree roots,
- for append-only-ness (aka. update consistency), by verifying the update proofs. (TODO: not yet implemented)

## Usage

```bash
./protonkt-monitor /path/to/monitoring/data
./protonkt-monitor --help
```

The `<data-dir>` is used to persist data across monitoring runs.
This allows monitoring to pick up where it left off.

## License

protonkt-monitor is dual-licensed under MIT and Apache 2.0 (like most of the Rust ecosystem).
