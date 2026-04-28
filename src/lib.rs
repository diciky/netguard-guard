// NetGuard library entry point
// This module provides the core functionality that can be called from main.rs
// Note: This is only used when building as a library; for binary, main.rs has its own mod declarations

pub mod types;
pub mod nflog_listener;
pub mod sni_parser;
pub mod app_identifier;
pub mod flow_tracker;
pub mod history_aggregator;
pub mod nftables_counter;
pub mod persistence;
pub mod api_server;
pub mod config;
pub mod nft_setup;