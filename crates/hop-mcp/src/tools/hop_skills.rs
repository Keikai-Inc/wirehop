//! hop_skills tool: encyclopedic skill lookup.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::protocol::{ToolCallResult, ToolDefinition};
use crate::skills::SkillStore;

#[derive(Debug, Deserialize)]
struct SkillsArgs {
    query: Option<String>,
    category: Option<String>,
    skill_id: Option<String>,
}

pub fn tool_definition() -> ToolDefinition {
    ToolDefinition {
        name: "hop_skills".into(),
        description: "Look up hop documentation, code examples, and operational recipes. Call this before writing hop_exec code to understand available APIs and best practices.".into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Natural language search (e.g. 'check disk usage across fleet')"
                },
                "category": {
                    "type": "string",
                    "enum": ["getting-started", "fleet", "roles", "admin", "discover", "install", "services", "monitor", "security", "files", "troubleshoot", "recipes"],
                    "description": "Browse skills by category"
                },
                "skill_id": {
                    "type": "string",
                    "description": "Direct lookup by ID (e.g. 'monitoring/cpu-usage')"
                }
            }
        }),
    }
}

pub fn call(store: &SkillStore, args: Value) -> ToolCallResult {
    let args: SkillsArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return ToolCallResult::error(format!("Invalid arguments: {e}")),
    };

    // Priority: skill_id > category > query > list categories
    if let Some(ref skill_id) = args.skill_id {
        return match store.get_with_sub_skills(skill_id) {
            Some(skills) => {
                if skills.len() == 1 {
                    let text = serde_json::to_string_pretty(skills[0]).unwrap_or_default();
                    ToolCallResult::text(text)
                } else {
                    // Intent skill with sub-skills: serialize all together
                    let text = serde_json::to_string_pretty(&skills).unwrap_or_default();
                    ToolCallResult::text(text)
                }
            }
            None => ToolCallResult::error(format!("Skill not found: {skill_id}")),
        };
    }

    if let Some(ref category) = args.category {
        let skills = store.list_category(category);
        if skills.is_empty() {
            return ToolCallResult::error(format!("No skills in category: {category}"));
        }
        let text = format!(
            "## {} ({} skills)\n\n{}",
            category,
            skills.len(),
            skills
                .iter()
                .map(|s| format!("- **{}** — {}\n  ID: `{}`", s.title, s.description, s.id))
                .collect::<Vec<_>>()
                .join("\n")
        );
        return ToolCallResult::text(text);
    }

    if let Some(ref query) = args.query {
        let results = store.search(query, 5);
        if results.is_empty() {
            return ToolCallResult::text(format!("No skills matched: \"{query}\". Try a broader query or browse by category."));
        }
        let text = format!(
            "## Search results for \"{}\"\n\n{}",
            query,
            results
                .iter()
                .map(|r| format!(
                    "- **{}** (score: {:.1})\n  {}\n  ID: `{}`",
                    r.title, r.score, r.description, r.id
                ))
                .collect::<Vec<_>>()
                .join("\n")
        );
        return ToolCallResult::text(text);
    }

    // No arguments — list all categories
    let cats = store.categories();
    let text = format!(
        "## hop Skills Categories\n\n{}\n\nUse `category` to browse, `skill_id` for direct lookup, or `query` to search.",
        cats.iter()
            .map(|(cat, count)| format!("- **{}** ({} skills)", cat, count))
            .collect::<Vec<_>>()
            .join("\n")
    );
    ToolCallResult::text(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_categories_with_no_args() {
        let store = SkillStore::new();
        let result = call(&store, json!({}));
        assert!(result.is_error.is_none());
        assert!(result.content[0].text.contains("Skills Categories"));
    }

    #[test]
    fn search_by_query() {
        let store = SkillStore::new();
        let result = call(&store, json!({"query": "cpu"}));
        assert!(result.is_error.is_none());
        assert!(result.content[0].text.contains("Search results"));
    }

    #[test]
    fn direct_lookup() {
        let store = SkillStore::new();
        let result = call(&store, json!({"skill_id": "monitor/cpu-usage"}));
        assert!(result.is_error.is_none());
    }

    #[test]
    fn category_browse() {
        let store = SkillStore::new();
        let result = call(&store, json!({"category": "monitor"}));
        assert!(result.is_error.is_none());
    }

    #[test]
    fn intent_skill_inlines_sub_skills() {
        let store = SkillStore::new();
        let result = call(&store, json!({"skill_id": "install/package"}));
        assert!(result.is_error.is_none());
        // Should contain sub-skill IDs
        let text = &result.content[0].text;
        assert!(text.contains("install/package-apt"));
    }

    #[test]
    fn unknown_skill_id() {
        let store = SkillStore::new();
        let result = call(&store, json!({"skill_id": "nonexistent/skill"}));
        assert_eq!(result.is_error, Some(true));
    }
}
