use axum::{
    routing::{get, post},
    Router,
    Json,
    Extension,
    http::{header, HeaderMap},
    response::IntoResponse,
};
use std::net::SocketAddr;
use tracing::{info, error};
use std::sync::Arc;
use std::path::PathBuf;
use serde_json::json;
use tower_http::services::ServeDir;

use crate::plugins::cache::CachePlugin;
use crate::stats::{DnsStats, STATS};

#[derive(Clone)]
pub struct AppState {
    pub cache: Option<Arc<CachePlugin>>,
    pub stats: Option<Arc<DnsStats>>,
    pub www_dir: Option<PathBuf>,
    pub config_file: PathBuf,
}

/// Start the API server with Dashboard support
pub async fn start_api_server(addr: SocketAddr, state: AppState) {
    // Determine the directory to serve. If not configured, default to "www" in current dir.
    let www_path = state.www_dir.clone().unwrap_or_else(|| PathBuf::from("www"));
    info!("📂 Serving dashboard from: {:?}", www_path);
    
    // API Routes
    let api_routes = Router::new()
        .route("/api/stats", get(get_dashboard_stats))
        .route("/api/config", get(get_config).post(update_config))
        .route("/api/health", get(health_check))
        .route("/api/logs", get(get_query_logs)) // New Logs API
        // === AutoPilot AIOps API ===
        .route("/api/autopilot/status", get(get_autopilot_status))
        .route("/api/autopilot/upstreams", get(get_upstream_health))
        .route("/api/autopilot/hot", get(get_hot_domains))
        .route("/api/autopilot/qps", get(get_qps_stats))
        .route("/api/autopilot/ranking", get(get_upstream_ranking)) // Level 8
        .route("/api/autopilot/suggestions", get(get_optimization_suggestions)) // Level 9
        .route("/stats", get(get_stats)) // Legacy endpoint
        .route("/cache/purge", post(purge_cache));

    // Combine API routes with Static File Service using ServeDir
    // We use nest_service to handle the static files at the root "/"
    let app = Router::new()
        .merge(api_routes)
        .nest_service("/", ServeDir::new(www_path))
        .layer(Extension(state));

    info!("🌐 Dashboard & API server listening on http://{}", addr);
    
    match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            if let Err(e) = axum::serve(listener, app).await {
                error!("API Server Error: {}", e);
            }
        },
        Err(e) => {
             error!("Failed to bind API port {}: {}", addr, e);
        }
    }
}

/// Helper to create no-cache headers
fn no_cache_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();

    // Safely parse header values with fallbacks
    let cache_control = "no-cache, no-store, must-revalidate".parse();
    if let Ok(value) = cache_control {
        headers.insert(header::CACHE_CONTROL, value);
    }

    let pragma = "no-cache".parse();
    if let Ok(value) = pragma {
        headers.insert(header::PRAGMA, value);
    }

    let expires = "0".parse();
    if let Ok(value) = expires {
        headers.insert(header::EXPIRES, value);
    }

    headers
}

/// GET /api/stats - Dashboard statistics
async fn get_dashboard_stats(Extension(state): Extension<AppState>) -> impl IntoResponse {
    let mut snapshot = STATS.snapshot().await;
    
    // Enrich with real cache stats if available
    if let Some(cache) = &state.cache {
        let (entries, bytes) = cache.stats();
        snapshot.cache_entries = entries;
        snapshot.cache_memory_bytes = bytes;
    }

    let data = json!({
        "total_queries": snapshot.total_queries,
        "cache_hits": snapshot.cache_hits,
        "cache_misses": snapshot.cache_misses,
        "cache_hit_rate": snapshot.cache_hit_rate,
        "blocked_count": snapshot.blocked_count,
        "avg_latency_ms": snapshot.avg_latency_ms,
        "top_domains": snapshot.top_domains,
        "top_clients": snapshot.top_clients,
        "recent_blocked": snapshot.recent_blocked,
        "cache_entries": snapshot.cache_entries,
        "cache_memory_bytes": snapshot.cache_memory_bytes,
        "uptime_seconds": snapshot.uptime_seconds,
        "xdp_hits": snapshot.xdp_hits, // [Fix] Expose XDP stats
        "rcode_breakdown": snapshot.rcode_breakdown,
        "qtype_breakdown": snapshot.qtype_breakdown,
        "strategy_breakdown": snapshot.strategy_breakdown,
    });

    (no_cache_headers(), Json(data))
}

/// GET /api/health - Health check
async fn health_check() -> &'static str {
    "OK"
}

/// GET /stats - Legacy stats endpoint
async fn get_stats(Extension(state): Extension<AppState>) -> impl IntoResponse {
    let cache_count = if let Some(c) = &state.cache {
        c.stats().0 // Get entry count only
    } else {
        0
    };

    let data = json!({
        "status": "ok",
        "cache_entries": cache_count,
        "TitanDNS": "v0.1.0"
    });
    
    (no_cache_headers(), Json(data))
}

/// POST /cache/purge - Clear cache
async fn purge_cache(Extension(state): Extension<AppState>) -> Json<serde_json::Value> {
    if let Some(c) = &state.cache {
        c.purge();
        Json(json!({ "status": "cache_purged", "message": "All cache entries invalidated" }))
    } else {
        Json(json!({ "status": "error", "message": "No cache plugin active" }))
    }
}

/// Query Parameters for logs
#[derive(serde::Deserialize)]
struct LogParams {
    limit: Option<usize>,
}

/// GET /api/logs - Recent Query Logs
async fn get_query_logs(axum::extract::Query(params): axum::extract::Query<LogParams>) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(100);
    // Hard cap at 1000 to prevent DoS
    let limit = std::cmp::min(limit, 1000);
    let logs = crate::query_log::get_recent_logs(limit).await;
    
    (no_cache_headers(), Json(logs))
}

/// GET /api/config
async fn get_config(Extension(state): Extension<AppState>) -> impl IntoResponse {
    match crate::config::Config::load_from_file(&state.config_file) {
        Ok(c) => (no_cache_headers(), Json(c)).into_response(),
        Err(e) => (
             axum::http::StatusCode::INTERNAL_SERVER_ERROR, 
             format!("Failed to load config: {}", e)
        ).into_response()
    }
}

/// POST /api/config
async fn update_config(
    Extension(state): Extension<AppState>, 
    Json(new_config): Json<crate::config::Config>
) -> impl IntoResponse {
    match serde_yaml::to_string(&new_config) {
        Ok(yaml) => {
            if let Err(e) = std::fs::write(&state.config_file, yaml) {
                 return (axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to write config: {}", e)).into_response();
            }
            (axum::http::StatusCode::OK, Json(json!({"status": "ok", "message": "Config updated, hot reload triggered"}))).into_response()
        },
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, format!("Invalid config format: {}", e)).into_response()
    }
}

// ============== AutoPilot AIOps API ==============

/// GET /api/autopilot/status - Overall AutoPilot status
async fn get_autopilot_status() -> impl IntoResponse {
    let data = json!({
        "status": "running",
        "udp_blocked": crate::autopilot::is_udp_blocked(),
        "registered_upstreams": crate::autopilot::AUTOPILOT.get_upstream_count(),
        "hot_domains_count": crate::autopilot::HOT_DOMAINS.get_domain_count(),
        "current_qps": crate::autopilot::get_current_qps(),
        "avg_qps_30s": crate::autopilot::get_avg_qps(30),
    });
    (no_cache_headers(), Json(data))
}

/// GET /api/autopilot/upstreams - Detailed upstream health
async fn get_upstream_health() -> impl IntoResponse {
    let upstreams = crate::autopilot::AUTOPILOT.get_all_upstreams();
    
    let upstream_list: Vec<serde_json::Value> = upstreams.iter().map(|u| {
        json!({
            "label": u.label,
            "score": u.get_score(),
            "avg_rtt_ms": u.get_avg_rtt(),
            "min_rtt_ms": u.get_min_rtt(),
            "max_rtt_ms": u.get_max_rtt(),
            "p95_rtt_ms": u.get_p95_latency(),
            "jitter_ms": u.get_jitter_ms(),
            "success_rate": u.get_success_rate(),
            "packet_loss_rate": u.get_packet_loss_rate(),
            "healthy": u.is_available(),
        })
    }).collect();
    
    let best = crate::autopilot::AUTOPILOT.get_best_upstreams();
    
    let data = json!({
        "upstreams": upstream_list,
        "best_upstream": best.first(),
        "ranked_order": best,
    });
    
    (no_cache_headers(), Json(data))
}

/// GET /api/autopilot/hot - Hot domains list
async fn get_hot_domains() -> impl IntoResponse {
    let hot = crate::autopilot::get_hot_domains(100);
    let prefetch = crate::autopilot::get_prefetch_list(0.2);
    
    let hot_list: Vec<serde_json::Value> = hot.iter().map(|(domain, count)| {
        json!({
            "domain": domain,
            "access_count": count,
        })
    }).collect();
    
    let data = json!({
        "hot_domains": hot_list,
        "hot_domain_count": hot.len(),
        "prefetch_candidates": prefetch,
        "prefetch_count": prefetch.len(),
    });
    
    (no_cache_headers(), Json(data))
}

// ... (existing code)

/// GET /api/autopilot/suggestions - Level 9: AI Optimization Suggestions
async fn get_optimization_suggestions() -> impl IntoResponse {
    let suggestions = crate::autopilot::generate_optimization_suggestions();
    (no_cache_headers(), Json(suggestions))
}

/// GET /api/autopilot/ranking - Level 8: Explicit Upstream Ranking
async fn get_upstream_ranking() -> impl IntoResponse {
    let rankings = crate::autopilot::get_upstream_rankings();
    let json_rankings: Vec<serde_json::Value> = rankings.iter().map(|r| {
        json!({
            "rank": r.rank,
            "label": r.label,
            "score": r.score,
            "avg_latency_ms": r.avg_latency_ms,
            "success_rate": r.success_rate,
            "packet_loss": r.packet_loss,
            "status": r.status,
        })
    }).collect();
    (no_cache_headers(), Json(json_rankings))
}

/// GET /api/autopilot/qps - QPS statistics
async fn get_qps_stats() -> impl IntoResponse {
    let tracker = &crate::autopilot::QPS_TRACKER;
    
    let data = json!({
        "current_qps": tracker.get_current_qps(),
        "avg_qps_10s": tracker.get_avg_qps(10),
        "avg_qps_30s": tracker.get_avg_qps(30),
        "avg_qps_60s": tracker.get_avg_qps(60),
        "peak_qps_60s": tracker.get_peak_qps(),
        "trend_percent": tracker.get_trend(),
    });
    
    (no_cache_headers(), Json(data))
}

