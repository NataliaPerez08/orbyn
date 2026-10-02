//! Migration wave planning (Phase 10 of `docs/ORBYN_AGENT_PLAN.md`).
//!
//! Suggests ordered migration waves from the dependency graph, application
//! groups, criticality, migration complexity, external coupling and manual
//! constraints. Waves are risk-banded so every asset lands where it does
//! because of the reasons it carries — never a mystery number.
//!
//! The planner is a pure function over an [`AssessmentReport`] + [`AssessmentInput`]
//! (the same snapshot `orbyn assess` builds); manual constraints arrive as
//! `--pin`/`--exclude`.

use std::collections::HashMap;

use serde::Serialize;

use crate::assessment::{
    complexity_band, external_endpoints, AssessmentInput, AssessmentReport, Complexity,
};
use crate::domain::{Asset, Criticality, Dependency, EvidenceKind};
use crate::output::Format;

/// Labels mirroring the risk bands of `ORBYN_AGENT_PLAN.md`.
pub const WAVE_LABELS: [&str; 3] = ["low risk", "medium risk", "high risk / core"];

/// An asset assigned to a wave, with the reasons that placed it there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WaveAsset {
    pub asset_id: String,
    /// Risk score 0-9 (higher = migrate later).
    pub score: u8,
    /// One reason per contributing factor.
    pub reasons: Vec<String>,
}

/// One migration wave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Wave {
    /// 1-based wave number.
    pub index: usize,
    pub label: &'static str,
    pub assets: Vec<WaveAsset>,
}

/// The complete wave plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WavePlan {
    pub waves: Vec<Wave>,
    /// Assets left out of planning via `--exclude`.
    pub excluded: Vec<String>,
    /// Pins referencing assets that are not in the inventory.
    pub warnings: Vec<String>,
}

/// Build the migration wave plan.
///
/// `pins` force an asset — and any application group it belongs to — into a
/// specific 1-based wave. `excludes` leave assets out of planning.
pub fn plan_waves(
    report: &AssessmentReport,
    input: &AssessmentInput,
    pins: &[(String, usize)],
    excludes: &[String],
) -> WavePlan {
    let excluded: std::collections::HashSet<&str> = excludes.iter().map(String::as_str).collect();
    let external = external_endpoints(&input.assets, &input.connections);
    let unconfirmed = unconfirmed_dep_counts(&input.dependencies);
    let scores: HashMap<&str, u8> = report
        .asset_scores
        .iter()
        .map(|s| (s.asset_id.as_str(), s.score))
        .collect();
    let asset_meta: HashMap<&str, WaveAsset> = input
        .assets
        .iter()
        .map(|a| {
            (
                a.id.as_str(),
                score_asset(a, &scores, &external, &unconfirmed),
            )
        })
        .collect();

    // Units are application groups or singletons; a group migrates together.
    let group_ids: std::collections::HashSet<&str> = report
        .application_groups
        .iter()
        .map(|g| g.id.as_str())
        .collect();
    let mut units: Vec<(&str, Vec<&str>)> = Vec::new();
    let mut in_unit: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for group in &report.application_groups {
        units.push((
            group.id.as_str(),
            group.asset_ids.iter().map(String::as_str).collect(),
        ));
        in_unit.extend(group.asset_ids.iter().map(String::as_str));
    }
    for asset in &input.assets {
        if !in_unit.contains(asset.id.as_str()) {
            units.push((asset.id.as_str(), vec![asset.id.as_str()]));
        }
    }

    let unit_score: HashMap<&str, u8> = units
        .iter()
        .map(|(id, members)| {
            let max = members
                .iter()
                .map(|m| asset_meta[m].score)
                .max()
                .unwrap_or(0);
            (*id, max)
        })
        .collect();

    let known: std::collections::HashSet<&str> =
        input.assets.iter().map(|a| a.id.as_str()).collect();
    let warnings: Vec<String> = pins
        .iter()
        .filter(|(id, _)| !known.contains(id.as_str()))
        .map(|(id, _)| format!("pin ignored: {id} is not in the inventory"))
        .collect();

    let mut waves: Vec<Wave> = (0..3)
        .map(|i| Wave {
            index: i + 1,
            label: WAVE_LABELS[i],
            assets: Vec::new(),
        })
        .collect();

    let mut sorted = units;
    sorted.sort_by(|(a_id, _), (b_id, _)| {
        unit_score[a_id]
            .cmp(&unit_score[b_id])
            .then_with(|| a_id.cmp(b_id))
    });

    for (unit_id, members) in sorted {
        let remaining: Vec<&str> = members
            .iter()
            .copied()
            .filter(|m| !excluded.contains(m))
            .collect();
        if remaining.is_empty() {
            continue;
        }

        let mut idx = band(unit_score[unit_id]);
        let mut pinned = false;
        for (pin_asset, wave) in pins {
            if members.contains(&pin_asset.as_str()) {
                idx = (*wave).clamp(1, 3);
                pinned = true;
                break;
            }
        }

        for m in remaining {
            let mut wa = asset_meta[m].clone();
            if group_ids.contains(unit_id) {
                wa.reasons
                    .push(format!("member of {unit_id} (migrates as one unit)"));
            }
            if pinned {
                wa.reasons.push(format!("pinned to wave {idx} via --pin"));
            }
            waves[idx - 1].assets.push(wa);
        }
    }

    for wave in &mut waves {
        wave.assets.sort_by(|a, b| {
            a.score
                .cmp(&b.score)
                .then_with(|| a.asset_id.cmp(&b.asset_id))
        });
    }
    let mut excluded_ids: Vec<String> = input
        .assets
        .iter()
        .map(|a| a.id.clone())
        .filter(|id| excluded.contains(id.as_str()))
        .collect();
    excluded_ids.sort();

    WavePlan {
        waves: waves.into_iter().filter(|w| !w.assets.is_empty()).collect(),
        excluded: excluded_ids,
        warnings,
    }
}

/// Risk score 0-9: environment + criticality + complexity band, plus one point
/// each for external coupling and unconfirmed dependencies.
fn score_asset(
    asset: &Asset,
    scores: &HashMap<&str, u8>,
    external: &HashMap<String, Vec<String>>,
    unconfirmed: &HashMap<String, usize>,
) -> WaveAsset {
    let mut score = 0u8;
    let mut reasons = Vec::new();
    let assessment_score = scores.get(asset.id.as_str()).copied().unwrap_or(0);

    match asset.environment.as_deref().map(str::to_ascii_lowercase) {
        Some(env) if is_nonprod(&env) => reasons.push(format!("environment {env}")),
        Some(env) => {
            score += 2;
            reasons.push(format!("production environment {env}"));
        }
        None => {
            score += 1;
            reasons.push("environment unset (treated as neutral)".into());
        }
    }

    match asset.criticality {
        Some(Criticality::Low) => reasons.push("criticality low".into()),
        Some(Criticality::Medium) => {
            score += 1;
            reasons.push("criticality medium".into());
        }
        Some(Criticality::High) => {
            score += 2;
            reasons.push("criticality high".into());
        }
        Some(Criticality::Critical) => {
            score += 3;
            reasons.push("criticality critical".into());
        }
        None => {
            score += 2;
            reasons.push("criticality unset (treated as high)".into());
        }
    }

    let band = complexity_band(assessment_score);
    score += match band {
        Complexity::Low => 0,
        Complexity::Medium => 1,
        Complexity::High => 2,
    };
    reasons.push(format!("complexity {band} (score {assessment_score}/100)"));

    if let Some(endpoints) = external.get(&asset.id) {
        if !endpoints.is_empty() {
            score += 1;
            reasons.push(format!("{} external endpoint(s)", endpoints.len()));
        }
    }

    if let Some(&n) = unconfirmed.get(&asset.id) {
        if n > 0 {
            score += 1;
            reasons.push(format!("{n} unconfirmed dependency edge(s)"));
        }
    }

    WaveAsset {
        asset_id: asset.id.clone(),
        score,
        reasons,
    }
}

fn is_nonprod(env: &str) -> bool {
    matches!(
        env,
        "dev"
            | "test"
            | "qa"
            | "stage"
            | "staging"
            | "int"
            | "integration"
            | "uat"
            | "sit"
            | "dr"
            | "lab"
    )
}

/// Risk band to a 1-based wave: 0-3 low, 4-6 medium, 7+ high.
fn band(score: u8) -> usize {
    match score {
        0..=3 => 1,
        4..=6 => 2,
        _ => 3,
    }
}

/// Unconfirmed (observed, not yet confirmed) non-DNS dependency edges per
/// asset — the `dep.unconfirmed` signal, counted in both directions.
fn unconfirmed_dep_counts(deps: &[Dependency]) -> HashMap<String, usize> {
    let mut out: HashMap<String, usize> = HashMap::new();
    for d in deps {
        if d.confirmed || d.evidence_kind() == EvidenceKind::Dns {
            continue;
        }
        *out.entry(d.source_asset_id.clone()).or_default() += 1;
        *out.entry(d.target_asset_id.clone()).or_default() += 1;
    }
    out
}

/// Render the plan for `orbyn waves`.
pub fn render(
    report: &AssessmentReport,
    input: &AssessmentInput,
    pins: &[(String, usize)],
    excludes: &[String],
    format: Format,
) -> String {
    let plan = plan_waves(report, input, pins, excludes);
    if plan.waves.is_empty() {
        return "no assets to plan; import an inventory first\n".into();
    }
    match format {
        Format::Json => serde_json::to_string_pretty(&plan).unwrap_or_else(|_| "{}".into()),
        Format::Csv => {
            let mut out = String::from("wave,label,asset,score,reasons\n");
            for w in &plan.waves {
                for a in &w.assets {
                    out.push_str(&format!(
                        "{},{},{},{},{}\n",
                        w.index,
                        w.label,
                        a.asset_id,
                        a.score,
                        a.reasons.join("; ")
                    ));
                }
            }
            out
        }
        Format::Table => {
            let mut t = crate::output::table(&["Wave", "Asset", "Score", "Reasons"]);
            for w in &plan.waves {
                for a in &w.assets {
                    t.add_row(vec![
                        comfy_table::Cell::new(format!("{} ({})", w.index, w.label)),
                        comfy_table::Cell::new(&a.asset_id),
                        comfy_table::Cell::new(a.score),
                        comfy_table::Cell::new(a.reasons.join("; ")),
                    ]);
                }
            }
            let mut out = crate::output::render_table(t);
            if !plan.excluded.is_empty() {
                out.push_str(&format!("\nexcluded: {}\n", plan.excluded.join(", ")));
            }
            for msg in &plan.warnings {
                out.push_str(&format!("warning: {msg}\n"));
            }
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assessment::{ApplicationGroup, AssetScore};
    use chrono::Utc;

    fn asset(id: &str, env: Option<&str>, criticality: Option<Criticality>) -> Asset {
        Asset {
            id: id.into(),
            ip: format!("10.0.0.{}", id.len()).parse().unwrap(),
            hostname: None,
            device_class: None,
            os_name: None,
            os_version: None,
            sys_descr: None,
            environment: env.map(String::from),
            owner: None,
            criticality,
            tags: Vec::new(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
        }
    }

    fn report(
        assets: &[Asset],
        groups: Vec<ApplicationGroup>,
        scores: &[(&str, u8)],
    ) -> AssessmentReport {
        AssessmentReport {
            rules_version: "0.8.0".into(),
            assets_assessed: assets.len(),
            overall_score: 0,
            complexity: Complexity::Low,
            findings: Vec::new(),
            asset_scores: assets
                .iter()
                .map(|a| {
                    let score = scores
                        .iter()
                        .find(|(id, _)| *id == a.id)
                        .map(|(_, s)| *s)
                        .unwrap_or(5);
                    AssetScore {
                        asset_id: a.id.clone(),
                        score,
                        findings: 0,
                    }
                })
                .collect(),
            application_groups: groups,
        }
    }

    fn plan(assets: &[Asset], groups: Vec<ApplicationGroup>) -> WavePlan {
        plan_waves(
            &report(assets, groups, &[]),
            &AssessmentInput {
                assets: assets.to_vec(),
                ..Default::default()
            },
            &[],
            &[],
        )
    }

    fn wave_ids(plan: &WavePlan, index: usize) -> Vec<String> {
        plan.waves
            .iter()
            .find(|w| w.index == index)
            .map(|w| w.assets.iter().map(|a| a.asset_id.clone()).collect())
            .unwrap_or_default()
    }

    #[test]
    fn low_risk_dev_assets_land_in_wave_1() {
        let dev = asset("dev", Some("dev"), Some(Criticality::Low));
        let p = plan(&[dev], vec![]);
        assert_eq!(wave_ids(&p, 1), vec!["dev".to_string()]);
        assert_eq!(wave_ids(&p, 3), Vec::<String>::new());
    }

    #[test]
    fn production_critical_core_lands_in_wave_3() {
        let db = asset("db", Some("prod"), Some(Criticality::Critical));
        let p = plan_waves(
            &report(std::slice::from_ref(&db), vec![], &[("db", 60)]),
            &AssessmentInput {
                assets: vec![db],
                ..Default::default()
            },
            &[],
            &[],
        );
        assert_eq!(wave_ids(&p, 3), vec!["db".to_string()]);
    }

    #[test]
    fn coupled_assets_move_as_one_unit() {
        let a = asset("a", Some("dev"), Some(Criticality::Low));
        let b = asset("b", Some("prod"), Some(Criticality::Critical));
        let group = ApplicationGroup {
            id: "app-1".into(),
            asset_ids: vec!["a".into(), "b".into()],
            edge_count: 1,
        };
        let p = plan_waves(
            &report(&[a.clone(), b.clone()], vec![group], &[("b", 60)]),
            &AssessmentInput {
                assets: vec![a.clone(), b.clone()],
                ..Default::default()
            },
            &[],
            &[],
        );
        let mut both: Vec<String> = wave_ids(&p, 3);
        both.sort();
        assert_eq!(both, vec!["a".to_string(), "b".to_string()]);
        let wa = &p.waves[0].assets;
        assert!(
            wa.iter()
                .any(|x| x.reasons.iter().any(|r| r.contains("member of app-1"))),
            "{wa:?}"
        );
    }

    #[test]
    fn pin_forces_the_whole_group_into_a_wave() {
        let a = asset("a", Some("dev"), Some(Criticality::Low));
        let b = asset("b", Some("dev"), Some(Criticality::Low));
        let group = ApplicationGroup {
            id: "app-1".into(),
            asset_ids: vec!["a".into(), "b".into()],
            edge_count: 1,
        };
        let p = plan_waves(
            &report(&[a.clone(), b.clone()], vec![group], &[]),
            &AssessmentInput {
                assets: vec![a.clone(), b.clone()],
                ..Default::default()
            },
            &[("a".to_string(), 3)],
            &[],
        );
        assert_eq!(wave_ids(&p, 3), vec!["a".to_string(), "b".to_string()]);
        let reasons = &p.waves[0].assets[0].reasons;
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("pinned to wave 3 via --pin")),
            "{reasons:?}"
        );
    }

    #[test]
    fn exclude_removes_asset_and_lists_it() {
        let a = asset("a", Some("prod"), Some(Criticality::Critical));
        let b = asset("b", Some("dev"), Some(Criticality::Low));
        let p = plan_waves(
            &report(&[a.clone(), b.clone()], vec![], &[]),
            &AssessmentInput {
                assets: vec![a.clone(), b.clone()],
                ..Default::default()
            },
            &[],
            &["a".to_string()],
        );
        assert_eq!(wave_ids(&p, 1), vec!["b".to_string()]);
        assert_eq!(p.excluded, vec!["a".to_string()]);
    }

    #[test]
    fn unknown_pin_produces_a_warning() {
        let a = asset("a", Some("dev"), Some(Criticality::Low));
        let p = plan_waves(
            &report(std::slice::from_ref(&a), vec![], &[]),
            &AssessmentInput {
                assets: vec![a.clone()],
                ..Default::default()
            },
            &[("ghost".to_string(), 3)],
            &[],
        );
        assert!(!p.warnings.is_empty());
        assert!(p.warnings[0].contains("ghost"));
    }

    #[test]
    fn unset_criticality_is_treated_conservatively() {
        let unknown = asset("x", Some("dev"), None);
        let p = plan(&[unknown], vec![]);
        let wa = &p.waves[0].assets[0];
        assert!(
            wa.reasons.iter().any(|r| r.contains("treated as high")),
            "{:?}",
            wa.reasons
        );
    }

    #[test]
    fn reasons_expose_every_score_term() {
        let db = asset("db", Some("prod"), Some(Criticality::High));
        let p = plan(&[db], vec![]);
        let wa = &p.waves[0].assets[0];
        let all = wa.reasons.join(" ");
        for needle in [
            "production environment prod",
            "criticality high",
            "complexity low (score 5/100)",
        ] {
            assert!(all.contains(needle), "missing {needle:?} in {all:?}");
        }
    }

    #[test]
    fn unconfirmed_edges_add_a_point() {
        let a = asset("a", Some("dev"), Some(Criticality::Low));
        let b = asset("b", Some("dev"), Some(Criticality::Low));
        let deps = vec![Dependency {
            source_asset_id: "a".into(),
            target_asset_id: "b".into(),
            proto: "tcp".into(),
            port: 8080,
            evidence_source: "runtime".into(),
            confidence: 0.5,
            confirmed: false,
        }];
        let p = plan_waves(
            &report(&[a.clone(), b.clone()], vec![], &[]),
            &AssessmentInput {
                assets: vec![a.clone(), b.clone()],
                dependencies: deps,
                ..Default::default()
            },
            &[],
            &[],
        );
        let wa = &p.waves[0].assets[0];
        assert_eq!(wa.score, 1, "{:?}", wa.reasons);
        assert!(
            wa.reasons.iter().any(|r| r.contains("unconfirmed")),
            "{:?}",
            wa.reasons
        );
    }

    #[test]
    fn band_boundaries_are_stable() {
        assert_eq!(band(0), 1);
        assert_eq!(band(3), 1);
        assert_eq!(band(4), 2);
        assert_eq!(band(6), 2);
        assert_eq!(band(7), 3);
        assert_eq!(band(9), 3);
    }
}
