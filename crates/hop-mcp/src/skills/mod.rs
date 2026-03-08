//! Skill store: encyclopedic reference system for hop operations.
//!
//! Skills are embedded at compile time and searchable by ID, category, or keyword.

pub mod data;
pub(crate) mod categories;

use serde::Serialize;

/// A single skill entry.
#[derive(Debug, Clone, Serialize)]
pub struct Skill {
    pub id: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub tags: Vec<String>,
    pub prerequisites: Vec<String>,
    pub examples: Vec<SkillExample>,
    pub pitfalls: Vec<String>,
    pub related: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sub_skills: Vec<String>,
}

/// A code example within a skill.
#[derive(Debug, Clone, Serialize)]
pub struct SkillExample {
    pub title: String,
    pub code: String,
    pub expected_output: Option<String>,
}

/// Summary for category listing.
#[derive(Debug, Serialize)]
pub struct SkillSummary {
    pub id: String,
    pub title: String,
    pub description: String,
}

/// Search result entry.
#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub id: String,
    pub title: String,
    pub description: String,
    pub score: f32,
}

/// The skill store — holds all skills and provides lookup.
pub struct SkillStore {
    skills: Vec<Skill>,
}

impl Default for SkillStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SkillStore {
    /// Create a new skill store with all embedded skills.
    pub fn new() -> Self {
        Self {
            skills: data::all_skills(),
        }
    }

    /// Direct lookup by skill ID (e.g. "monitor/cpu-usage").
    pub fn get(&self, skill_id: &str) -> Option<&Skill> {
        self.skills.iter().find(|s| s.id == skill_id)
    }

    /// Lookup a skill and, if it has sub-skills, return the parent with all
    /// sub-skills inlined so the caller gets the full picture in one call.
    pub fn get_with_sub_skills(&self, skill_id: &str) -> Option<Vec<&Skill>> {
        let parent = self.get(skill_id)?;
        if parent.sub_skills.is_empty() {
            return Some(vec![parent]);
        }
        let mut result = vec![parent];
        for sub_id in &parent.sub_skills {
            if let Some(child) = self.get(sub_id) {
                result.push(child);
            }
        }
        Some(result)
    }

    /// List all skills in a category.
    pub fn list_category(&self, category: &str) -> Vec<SkillSummary> {
        self.skills
            .iter()
            .filter(|s| s.category == category)
            .map(|s| SkillSummary {
                id: s.id.clone(),
                title: s.title.clone(),
                description: s.description.clone(),
            })
            .collect()
    }

    /// Fuzzy keyword search across all skills. Returns top N matches.
    pub fn search(&self, query: &str, max_results: usize) -> Vec<SearchResult> {
        let query_lower = query.to_lowercase();
        let query_words: Vec<&str> = query_lower.split_whitespace().collect();

        let mut scored: Vec<SearchResult> = self
            .skills
            .iter()
            .filter_map(|skill| {
                let score = self.score_skill(skill, &query_words);
                if score > 0.0 {
                    Some(SearchResult {
                        id: skill.id.clone(),
                        title: skill.title.clone(),
                        description: skill.description.clone(),
                        score,
                    })
                } else {
                    None
                }
            })
            .collect();

        scored.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap());
        scored.truncate(max_results);
        scored
    }

    /// List all categories with counts.
    pub fn categories(&self) -> Vec<(String, usize)> {
        let mut cats: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();
        for skill in &self.skills {
            *cats.entry(skill.category.clone()).or_insert(0) += 1;
        }
        cats.into_iter().collect()
    }

    fn score_skill(&self, skill: &Skill, query_words: &[&str]) -> f32 {
        let mut score = 0.0f32;

        let title_lower = skill.title.to_lowercase();
        let desc_lower = skill.description.to_lowercase();
        let id_lower = skill.id.to_lowercase();
        let tags_lower: Vec<String> = skill.tags.iter().map(|t| t.to_lowercase()).collect();

        for word in query_words {
            // Title match (highest weight)
            if title_lower.contains(word) {
                score += 3.0;
            }
            // ID match
            if id_lower.contains(word) {
                score += 2.5;
            }
            // Tag match
            if tags_lower.iter().any(|t| t.contains(word)) {
                score += 2.0;
            }
            // Description match
            if desc_lower.contains(word) {
                score += 1.0;
            }
            // Example code match
            for ex in &skill.examples {
                if ex.code.to_lowercase().contains(word) {
                    score += 0.5;
                    break;
                }
            }
        }

        score
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_loads_skills() {
        let store = SkillStore::new();
        assert!(!store.skills.is_empty());
    }

    #[test]
    fn direct_lookup() {
        let store = SkillStore::new();
        let skill = store.get("monitor/cpu-usage");
        assert!(skill.is_some());
        assert_eq!(skill.unwrap().category, "monitor");
    }

    #[test]
    fn category_listing() {
        let store = SkillStore::new();
        let monitor = store.list_category("monitor");
        assert!(!monitor.is_empty());
    }

    #[test]
    fn search_returns_results() {
        let store = SkillStore::new();
        let results = store.search("disk usage", 5);
        assert!(!results.is_empty());
    }

    #[test]
    fn categories_returns_all() {
        let store = SkillStore::new();
        let cats = store.categories();
        assert!(cats.len() >= 4); // At minimum: getting-started, fleet, monitor, security
    }

    #[test]
    fn get_with_sub_skills_returns_children() {
        let store = SkillStore::new();
        let result = store.get_with_sub_skills("install/package");
        assert!(result.is_some());
        let skills = result.unwrap();
        assert!(skills.len() > 1); // Parent + at least one sub-skill
        assert_eq!(skills[0].id, "install/package");
    }

    #[test]
    fn get_with_sub_skills_leaf_skill() {
        let store = SkillStore::new();
        let result = store.get_with_sub_skills("monitor/disk-usage");
        assert!(result.is_some());
        let skills = result.unwrap();
        assert_eq!(skills.len(), 1); // Leaf skill, no sub-skills
    }
}
