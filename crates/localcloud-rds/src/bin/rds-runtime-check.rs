#[tokio::main]
async fn main() {
    match localcloud_rds::runtime::resolve_from_env().await {
        Ok(runtime) => {
            println!(
                "PostgreSQL {}: {}",
                runtime.version,
                runtime.bin_dir.display()
            );
        }
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
