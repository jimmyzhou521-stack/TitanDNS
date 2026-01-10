//! TTL Modifier Plugin (Refactored V2)
//!
//! 修改 DNS 响应的 TTL 值
//! 逻辑：如果设置了 fixed，则强制使用 fixed；否则应用 min/max 限制。

use anyhow::Result;
use tracing::debug;

use crate::core::context::Context;
use crate::core::plugin::Plugin;

#[derive(Debug, Clone)]
pub struct TtlPlugin {
    name: String,
    fixed: Option<u32>,
    min: Option<u32>,
    max: Option<u32>,
}

impl TtlPlugin {
    pub fn new(fixed: Option<u32>, min: Option<u32>, max: Option<u32>) -> Self {
        Self {
            name: "ttl".to_string(),
            fixed,
            min,
            max,
        }
    }

    fn apply_ttl(&self, ctx: &mut Context) {
        // 安全获取响应的可变引用
        let response = match &mut ctx.response {
            Some(r) => r,
            None => return,
        };

        let mut modified_count = 0;

        // 使用 answers_mut() 原地修改
        for answer in response.answers_mut() {
            let original_ttl = answer.ttl();
            let mut new_ttl = original_ttl;

            // 1. 如果有固定值，直接覆盖
            if let Some(fixed_ttl) = self.fixed {
                new_ttl = fixed_ttl;
            } else {
                // 2. 否则应用范围限制
                if let Some(min_ttl) = self.min {
                    if new_ttl < min_ttl {
                        new_ttl = min_ttl;
                    }
                }
                if let Some(max_ttl) = self.max {
                    if new_ttl > max_ttl {
                        new_ttl = max_ttl;
                    }
                }
            }

            // 只有真正改变时才设置
            if new_ttl != original_ttl {
                answer.set_ttl(new_ttl);
                modified_count += 1;
            }
        }

        if modified_count > 0 {
            debug!("⏱️ TTL: Modified {} records", modified_count);
        }
    }
}

impl Plugin for TtlPlugin {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        self.apply_ttl(ctx);
        Ok(())
    }
}
