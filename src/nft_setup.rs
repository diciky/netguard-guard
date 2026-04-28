use std::process::Command;

/// Setup nftables rules for NetGuard
pub fn setup() -> Result<(), std::io::Error> {
    // Create netguard table
    run_nft("add table inet netguard")?;

    // Create input chain
    run_nft("add chain inet netguard input { type filter hook input priority 0; policy accept; }")?;

    // Create output chain
    run_nft("add chain inet netguard output { type filter hook output priority 0; policy accept; }")?;

    // Add NFLog rule to output chain (group 100)
    run_nft("add rule inet netguard output tcp counter nflog group 100")?;

    log::info!("nftables rules created successfully");
    Ok(())
}

/// Run nft command and check result
fn run_nft(cmd: &str) -> Result<(), std::io::Error> {
    let output = Command::new("nft")
        .args(cmd.split_whitespace())
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ignore "file exists" errors
        if !stderr.contains("File exists") && !stderr.contains("No such file or directory") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("nft command failed: {}", stderr),
            ));
        }
    }
    Ok(())
}

/// Cleanup nftables rules
pub fn cleanup() -> Result<(), std::io::Error> {
    run_nft("delete table inet netguard")
}