//! Static skill content, embedded at compile time.

use super::{Skill, SkillExample};

pub(crate) fn s(v: &str) -> String {
    v.to_string()
}

pub(crate) fn tags(v: &[&str]) -> Vec<String> {
    v.iter().map(|t| t.to_string()).collect()
}

pub(crate) fn ex(title: &str, code: &str, expected: Option<&str>) -> SkillExample {
    SkillExample {
        title: s(title),
        code: s(code),
        expected_output: expected.map(|e| e.to_string()),
    }
}

pub fn all_skills() -> Vec<Skill> {
    let mut skills = Vec::new();
    skills.extend(super::categories::getting_started::skills());
    skills.extend(super::categories::fleet::skills());
    skills.extend(super::categories::roles::skills());
    skills.extend(super::categories::admin::skills());
    skills.extend(super::categories::discover::skills());
    skills.extend(super::categories::install::skills());
    skills.extend(super::categories::services::skills());
    skills.extend(super::categories::monitor::skills());
    skills.extend(super::categories::security::skills());
    skills.extend(super::categories::files::skills());
    skills.extend(super::categories::troubleshoot::skills());
    skills.extend(super::categories::recipes::skills());
    skills
}
