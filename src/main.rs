use std::sync::Arc;
use std::time::{SystemTime, Duration};
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};

mod types;
mod nflog_listener;
mod sni_parser;
mod app_identifier;
mod flow_tracker;
mod history_aggregator;
mod nftables_counter;
mod persistence;
mod api_server;
mod config;
mod nft_setup;

use nflog_listener::NflogListener;
use sni_parser::SniParser;
use app_identifier::AppIdentifier;
use flow_tracker::FlowTracker;
use history_aggregator::HistoryAggregator;
use nftables_counter::NftCounterReader;
use persistence::Persistence;
use config::Config;

const TIMEOUT_SECS: u64 = 60;
const BATCH_INTERVAL_SECS: u64 = 60;

fn main() {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    log::info!("NetGuard starting...");

    // Load configuration
    let cfg = Config::load();
    log::info!("Config loaded: enabled={}", cfg.enabled);

    // Setup nftables if enabled
    if cfg.enabled {
        if let Err(e) = nft_setup::setup() {
            log::warn!("nftables setup failed (may already exist): {}", e);
        }
    }

    // Create shared state
    let flow_tracker = Arc::new(FlowTracker::new());
    let history_aggregator = Arc::new(HistoryAggregator::new());

    // Create persistence layer (using Mutex for thread safety)
    let persistence = Arc::new(parking_lot::Mutex::new(
        match Persistence::new(&cfg.db_path) {
            Ok(p) => {
                log::info!("SQLite persistence initialized at {}", cfg.db_path);
                Some(p)
            }
            Err(e) => {
                log::error!("Failed to initialize SQLite: {}", e);
                None
            }
        }
    ));

    // Flag for graceful shutdown
    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    // Handle Ctrl+C
    ctrlc::set_handler(move || {
        log::info!("Received shutdown signal");
        running_clone.store(false, Ordering::SeqCst);
    }).ok();

    // Spawn NFLog listener thread
    let flow_tracker_listener = flow_tracker.clone();
    let app_id_for_listener = AppIdentifier::new();
    let running_for_listener = running.clone();
    let nflog_group = cfg.nflog_group;
    let listener_handle = thread::spawn(move || {
        log::info!("NFLog listener thread starting...");
        let mut sni_parser = SniParser::new();
        let mut packet_count: u64 = 0;

        while running_for_listener.load(Ordering::SeqCst) {
            match NflogListener::new(nflog_group) {
                Ok(listener) => {
                    let mut buf = [0u8; 65536];
                    loop {
                        if !running_for_listener.load(Ordering::SeqCst) {
                            break;
                        }
                        match listener.recv(&mut buf) {
                            Ok(n) => {
                                if n > 0 {
                                    packet_count += 1;
                                    if let Some((flow_key, _)) = nflog_listener::parse_packet(&buf[..n]) {
                                        if let Some(sni) = sni_parser.extract_sni(&buf[..n]) {
                                            if let Some((app_id, app_name)) = app_id_for_listener.identify_by_sni(&sni) {
                                                flow_tracker_listener.update_flow(flow_key, app_id, app_name, Some(sni), 0, 1);
                                            } else {
                                                flow_tracker_listener.update_flow(flow_key, "unknown".to_string(), "未知".to_string(), None, 0, 1);
                                            }
                                        } else {
                                            flow_tracker_listener.update_flow(flow_key, "unknown".to_string(), "未知".to_string(), None, 0, 1);
                                        }
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
                Err(e) => {
                    log::debug!("NFLog listener failed (need root privileges): {}", e);
                    thread::sleep(Duration::from_secs(5));
                }
            }
        }
        log::info!("NFLog listener thread stopped ({} packets)", packet_count);
    });

    // Spawn Stats thread (timeout detection + history aggregation + counter sync)
    let flow_tracker_stats = flow_tracker.clone();
    let history_stats = history_aggregator.clone();
    let counter_reader = Arc::new(NftCounterReader::new());
    let persistence_stats = persistence.clone();
    let running_for_stats = running.clone();
    let stats_handle = thread::spawn(move || {
        log::info!("Stats thread starting...");
        let interval = Duration::from_secs(10);
        let mut last_persist = SystemTime::now();

        while running_for_stats.load(Ordering::SeqCst) {
            let start = SystemTime::now();

            // Sync nftables counters
            let _counters = counter_reader.read_counters();

            // Cleanup timed-out flows and aggregate to history
            let timed_out = flow_tracker_stats.get_expired_flows(TIMEOUT_SECS);
            if !timed_out.is_empty() {
                log::info!("{} flows timed out", timed_out.len());
                for (flow_key, flow_value) in &timed_out {
                    history_stats.aggregate(&flow_key, &flow_value);
                }
                for (flow_key, _) in &timed_out {
                    flow_tracker_stats.remove_flow(flow_key);
                }
            }

            // Periodic persistence (every BATCH_INTERVAL_SECS)
            let elapsed = start.duration_since(last_persist).unwrap_or(Duration::ZERO);
            if elapsed.as_secs() >= BATCH_INTERVAL_SECS {
                last_persist = start;
                let history_data = history_stats.get_summary();
                if !history_data.is_empty() {
                    if let Some(ref p) = *persistence_stats.lock() {
                        p.batch_write(&history_data);
                        log::info!("Persisted {} history records", history_data.len());
                    }
                }
            }

            // Sleep remaining time to maintain ~10s interval
            let elapsed = start.elapsed().unwrap_or(Duration::from_secs(0));
            if elapsed < interval {
                thread::sleep(interval - elapsed);
            }
        }
        log::info!("Stats thread stopped");
    });

    // Wait for threads
    log::info!("All threads started, waiting for shutdown...");
    listener_handle.join().ok();
    stats_handle.join().ok();

    log::info!("NetGuard stopped");
}