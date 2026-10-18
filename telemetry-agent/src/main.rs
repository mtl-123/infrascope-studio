fn main() -> anyhow::Result<()> {
    infrascope_telemetry::cli(infrascope_telemetry::config::Kind::Host)
}
