use anyhow::Result;
use tracing::debug;
use crate::core::context::Context;
use crate::core::plugin::Plugin;
use crate::plugins::AnyPlugin;
use crate::config::MatchCondition;

#[derive(Debug)]
pub struct Sequence {
    pub name: String,
    pub steps: Vec<Step>,
    // Registry of plugins used for matching (e.g. MatcherPlugin)
    // Key: Plugin Name
    pub matchers_registry: std::collections::HashMap<String, AnyPlugin>,
}

#[derive(Debug)]
pub struct Step {
    pub conditions: Vec<MatchCondition>,
    pub plugin: AnyPlugin,
}

impl Plugin for Sequence {
    fn name(&self) -> &str {
        &self.name
    }

    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        for (i, step) in self.steps.iter().enumerate() {
            // 1. Check conditions
            if !self.check_match(ctx, &step.conditions) {
                continue;
            }

            // 2. Execute Plugin
            // NOTE: We call handle on the trait object directly. 
            // async_trait handles the object safety magic.
            step.plugin.handle(ctx).await?;

            if ctx.abort {
                debug!("Sequence '{}' stopped after step {}", self.name, i);
                break;
            }
        }
        Ok(())
    }
}

impl Sequence {
    fn check_match(&self, ctx: &Context, conditions: &[MatchCondition]) -> bool {
        if conditions.is_empty() {
            return true;
        }

        for cond in conditions {
            let matched = match cond {
                MatchCondition::ByQname { qname: patterns } => {
                    let qname = ctx.qname_ref();
                    patterns.iter().any(|p| qname.ends_with(p))
                },
                MatchCondition::ByQtype { qtype: types } => {
                    let qt = ctx.request.query().map(|q| u16::from(q.query_type())).unwrap_or(0);
                    types.contains(&qt)
                },
                MatchCondition::ByTag { has_tag: tag, invert } => {
                     let matched = ctx.has_tag(tag);
                     if *invert { !matched } else { matched }
                },
                MatchCondition::ByMatcherPlugin { match_plugin: plugin_name } => {
                    // Look up the matcher plugin and check if domain matches
                    if let Some(crate::plugins::AnyPlugin::Matcher(matcher)) = self.matchers_registry.get(plugin_name) {
                        matcher.matches(ctx.qname_ref())
                    } else {
                        tracing::warn!("Matcher plugin '{}' not found", plugin_name);
                        false
                    }
                },
                _ => false,
            };

            if !matched {
                return false;
            }
        }
        true
    }
}
