// Query Logging Plugin
// Records DNS queries for debugging and auditing

#![allow(dead_code)] // Framework implementation

use anyhow::Result;
use chrono::Local;
use hickory_proto::rr::RecordType;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::warn;

use crate::core::context::Context;
use crate::core::plugin::Plugin;

#[derive(Debug)]
pub struct QueryLogPlugin {
    pub name: String,
    log_file: Arc<Mutex<Option<std::fs::File>>>,
    log_queries: bool,
    log_responses: bool,
}

impl Clone for QueryLogPlugin {
    fn clone(&self) -> Self {
        Self {
            name: self.name.clone(),
            log_file: self.log_file.clone(),
            log_queries: self.log_queries,
            log_responses: self.log_responses,
        }
    }
}

impl QueryLogPlugin {
    pub fn new(log_path: Option<PathBuf>, log_queries: bool, log_responses: bool) -> Result<Self> {
        let log_file = if let Some(path) = log_path {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            Some(file)
        } else {
            None
        };

        Ok(Self {
            name: "query_log".to_string(),
            log_file: Arc::new(Mutex::new(log_file)),
            log_queries,
            log_responses,
        })
    }

    async fn log_entry(&self, entry: String) {
        let mut file_guard = self.log_file.lock().await;
        if let Some(file) = file_guard.as_mut() {
            if let Err(e) = writeln!(file, "{}", entry) {
                warn!("Failed to write query log: {}", e);
            }
            // Flush for real-time logging
            let _ = file.flush();
        }
    }

    fn format_query(&self, ctx: &Context) -> String {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let query = ctx.request.query();
        
        if let Some(q) = query {
            format!(
                "[{}] QUERY {} {} {} from {}",
                timestamp,
                ctx.request.id(),
                q.name(),
                q.query_type(),
                ctx.client_addr
            )
        } else {
            format!(
                "[{}] QUERY {} (invalid) from {}",
                timestamp,
                ctx.request.id(),
                ctx.client_addr
            )
        }
    }

    fn format_response(&self, ctx: &Context) -> String {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        
        if let Some(response) = &ctx.response {
            let query = ctx.request.query();
            let qname = if query.is_some() { ctx.qname_ref() } else { "?" };
            let qtype = query.map(|q| q.query_type()).unwrap_or(RecordType::Unknown(0));
            
            let rcode = response.response_code();
            let answer_count = response.answer_count();
            
            // Extract first answer if exists
            let first_answer = if answer_count > 0 {
                response.answers().first().map(|r| {
                    format!(" => {:?}", r.data())
                }).unwrap_or_default()
            } else {
                String::new()
            };
            
            format!(
                "[{}] RESPONSE {} {} {} rcode={:?} answers={}{} to {}",
                timestamp,
                ctx.request.id(),
                qname,
                qtype,
                rcode,
                answer_count,
                first_answer,
                ctx.client_addr
            )
        } else {
            format!(
                "[{}] RESPONSE {} (no response) to {}",
                timestamp,
                ctx.request.id(),
                ctx.client_addr
            )
        }
    }
}

impl Plugin for QueryLogPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        if self.log_queries {
            let entry = self.format_query(ctx);
            self.log_entry(entry).await;
        }
        Ok(())
    }

    async fn on_response(&self, ctx: &mut Context) -> Result<()> {
        if self.log_responses {
            let entry = self.format_response(ctx);
            self.log_entry(entry).await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::Name;
    use std::str::FromStr;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_query_log_creation() {
        let temp_file = NamedTempFile::new().unwrap();
        let plugin = QueryLogPlugin::new(
            Some(temp_file.path().to_path_buf()),
            true,
            true,
        ).unwrap();
        
        assert_eq!(plugin.log_queries, true);
        assert_eq!(plugin.log_responses, true);
    }

    #[tokio::test]
    async fn test_query_logging() {
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();
        
        let plugin = QueryLogPlugin::new(Some(path.clone()), true, false).unwrap();
        
        let mut message = Message::new();
        message.set_id(1234);
        let name = Name::from_str("example.com.").unwrap();
        let query = Query::query(name, RecordType::A);
        message.add_query(query);
        
        let mut ctx = Context::new(message, "127.0.0.1:12345".parse().unwrap());
        
        plugin.handle(&mut ctx).await.unwrap();
        
        // Give file system time to flush
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("QUERY"));
        assert!(content.contains("example.com"));
        assert!(content.contains("127.0.0.1:12345"));
    }
}
