//! Semantic validator for the M4 REALNET-60 evidence contract.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::{BTreeMap, BTreeSet}, fs, path::{Component, Path}};

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub protocol: String,
    pub campaign_id: String,
    pub build: Build,
    pub runs: Vec<Run>,
    #[serde(default)] pub artifacts: Vec<Artifact>,
}

#[derive(Debug, Deserialize)]
pub struct Build { pub git_sha: String }

#[derive(Debug, Deserialize)]
pub struct Run {
    pub run_id: String,
    pub scenario: String,
    pub validity: String,
    pub invalid_reason: Option<String>,
    pub build_sha: String,
    pub direct: Option<Direct>,
    pub reconnect: Option<Reconnect>,
    #[serde(default)] pub evidence_refs: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Direct {
    pub eligible: bool,
    pub ineligibility_reason: Option<String>,
    pub connected: bool,
    pub authenticated: bool,
    pub bidirectional_probe_passed: bool,
    pub stability_window_passed: bool,
    pub selected_candidate_type: Option<String>,
    pub result: String,
    pub failure_code: Option<String>,
    pub started_monotonic_ms: u64,
    pub final_decision_monotonic_ms: u64,
    pub connection_time_ms: Option<u64>,
    pub resolution_time_ms: u64,
    pub block_evidence_ref: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Reconnect {
    pub eligible: bool,
    pub disruption_verified: bool,
    pub attempt_started: bool,
    pub session_restored: bool,
    pub authenticated_after_restore: bool,
    pub result: String,
    pub failure_code: Option<String>,
    pub disruption_detected_monotonic_ms: Option<u64>,
    pub restored_monotonic_ms: Option<u64>,
    pub reconnect_time_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct Artifact {
    pub artifact_id: String,
    pub relative_path: String,
    pub kind: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Diagnostic {
    pub code: &'static str,
    pub severity: &'static str,
    pub category: &'static str,
    pub message: String,
    pub instance_path: String,
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Outcome { ValidM4Pass, ValidM4Fail, InvalidManifest }

#[derive(Debug, Serialize)]
pub struct Report {
    pub validator: &'static str,
    pub validator_version: &'static str,
    pub protocol: String,
    pub campaign_id: String,
    pub result: Outcome,
    pub diagnostics: Vec<Diagnostic>,
    pub metrics: Metrics,
}

#[derive(Debug, Default, Serialize)]
pub struct Metrics {
    pub valid_runs: usize,
    pub direct_eligible: usize,
    pub direct_passes: usize,
    pub overall_direct_rate_percent: Option<f64>,
    pub connection_p50_ms: Option<u64>,
    pub connection_p95_ms: Option<u64>,
    pub reconnect_eligible: usize,
    pub reconnect_passes: usize,
    pub reconnect_rate_percent: Option<f64>,
    pub reconnect_p50_ms: Option<u64>,
    pub reconnect_p95_ms: Option<u64>,
}

fn error(code: &'static str, category: &'static str, message: impl Into<String>, path: impl Into<String>, run_id: Option<&str>) -> Diagnostic {
    Diagnostic { code, severity:"ERROR", category, message:message.into(), instance_path:path.into(), run_id:run_id.map(str::to_owned) }
}
fn gate(code: &'static str, message: impl Into<String>, path: impl Into<String>) -> Diagnostic {
    Diagnostic { code, severity:"GATE_FAIL", category:"ACCEPTANCE_THRESHOLD", message:message.into(), instance_path:path.into(), run_id:None }
}
fn percentile(mut values: Vec<u64>, numerator: usize, denominator: usize) -> Option<u64> {
    if values.is_empty() { return None; }
    values.sort_unstable();
    let rank=(numerator*values.len()).div_ceil(denominator);
    values.get(rank.saturating_sub(1)).copied()
}
fn rate(pass:usize,total:usize)->Option<f64>{ if total==0 {None} else {Some(pass as f64*100.0/total as f64)} }
fn scenario_prefix(s:&str)->Option<&'static str>{
    match s {
        "T1_BROADBAND_BROADBAND"=>Some("M4-T1-"),"T2_BROADBAND_CGNAT"=>Some("M4-T2-"),
        "T3_CGNAT_CGNAT"=>Some("M4-T3-"),"T4_RESTRICTIVE_NETWORK"=>Some("M4-T4-"),
        "T5_IPV4_IPV6"=>Some("M4-T5-"),"T6_RECONNECT"=>Some("M4-T6-"),_=>None
    }
}

pub fn validate(manifest:&Manifest, package_root:Option<&Path>)->Report {
    let mut d=Vec::new();
    if manifest.protocol!="M4-REALNET-60-v1" { d.push(error("M4V-E1003","SCHEMA_PROTOCOL","unsupported protocol","/protocol",None)); }
    let mut ids=BTreeSet::new();
    let mut counts:BTreeMap<&str,usize>=BTreeMap::new();
    let mut direct_eligible=0; let mut direct_pass=0; let mut connection_times=Vec::new();
    let mut reconnect_eligible=0; let mut reconnect_pass=0; let mut reconnect_times=Vec::new();

    for (i,r) in manifest.runs.iter().enumerate() {
        let base=format!("/runs/{i}");
        if !ids.insert(&r.run_id) { d.push(error("M4V-E2004","RUN_ACCOUNTING","duplicate run_id",format!("{base}/run_id"),Some(&r.run_id))); }
        if let Some(p)=scenario_prefix(&r.scenario) {
            if !r.run_id.starts_with(p) { d.push(error("M4V-E2005","RUN_ACCOUNTING","run_id scenario prefix mismatch",format!("{base}/run_id"),Some(&r.run_id))); }
        }
        if r.validity=="VALID" {
            *counts.entry(&r.scenario).or_default()+=1;
            if r.invalid_reason.is_some(){d.push(error("M4V-E2006","RUN_ACCOUNTING","VALID run has invalid_reason",format!("{base}/invalid_reason"),Some(&r.run_id)));}
            if r.build_sha!=manifest.build.git_sha { d.push(error("M4V-E2009","RUN_ACCOUNTING","VALID run build SHA differs from campaign",format!("{base}/build_sha"),Some(&r.run_id))); }
            if r.scenario=="T6_RECONNECT" {
                if r.direct.is_some(){d.push(error("M4V-E2011","RUN_ACCOUNTING","T6 must not contribute a direct attempt",format!("{base}/direct"),Some(&r.run_id)));}
                match &r.reconnect {
                    Some(x)=>{
                        if x.eligible { reconnect_eligible+=1; }
                        if x.result=="PASS" {
                            reconnect_pass+=1;
                            if !(x.eligible&&x.disruption_verified&&x.attempt_started&&x.session_restored&&x.authenticated_after_restore&&x.failure_code.is_none()) {
                                d.push(error("M4V-E6001","RECONNECT_INVARIANT","reconnect PASS invariants violated",format!("{base}/reconnect"),Some(&r.run_id)));
                            }
                            if let Some(t)=x.reconnect_time_ms { reconnect_times.push(t); } else { d.push(error("M4V-E6004","RECONNECT_INVARIANT","reconnect PASS lacks time",format!("{base}/reconnect/reconnect_time_ms"),Some(&r.run_id))); }
                        } else if x.eligible && x.result=="FAIL" && x.failure_code.is_none() {
                            d.push(error("M4V-E6006","RECONNECT_INVARIANT","eligible reconnect FAIL lacks failure_code",format!("{base}/reconnect/failure_code"),Some(&r.run_id)));
                        }
                        if let (Some(a),Some(b),Some(stored))=(x.disruption_detected_monotonic_ms,x.restored_monotonic_ms,x.reconnect_time_ms) {
                            if b<a || b-a!=stored { d.push(error("M4V-E5005","TIMING","reconnect duration mismatch",format!("{base}/reconnect/reconnect_time_ms"),Some(&r.run_id))); }
                        }
                    }
                    None=>d.push(error("M4V-E2012","RUN_ACCOUNTING","VALID T6 lacks reconnect attempt",format!("{base}/reconnect"),Some(&r.run_id)))
                }
            } else {
                if r.reconnect.is_some(){d.push(error("M4V-E2011","RUN_ACCOUNTING","T1-T5 must not contain reconnect attempt",format!("{base}/reconnect"),Some(&r.run_id)));}
                match &r.direct {
                    Some(x)=>{
                        if x.eligible { direct_eligible+=1; }
                        if x.result=="PASS" {
                            if !(x.eligible&&x.connected&&x.authenticated&&x.bidirectional_probe_passed&&x.stability_window_passed&&x.failure_code.is_none()&&x.connection_time_ms.is_some()&&x.selected_candidate_type.as_deref()!=Some("RELAY")) {
                                d.push(error("M4V-E3001","DIRECT_INVARIANT","direct PASS invariants violated",format!("{base}/direct"),Some(&r.run_id)));
                            } else { direct_pass+=1; connection_times.push(x.connection_time_ms.unwrap_or_default()); }
                        } else if x.eligible && x.result=="FAIL" && x.failure_code.is_none() {
                            d.push(error("M4V-E3009","DIRECT_INVARIANT","eligible direct FAIL lacks failure_code",format!("{base}/direct/failure_code"),Some(&r.run_id)));
                        } else if !x.eligible {
                            if x.result!="INELIGIBLE" || x.ineligibility_reason.is_none() || x.connected || x.authenticated || x.connection_time_ms.is_some() {
                                d.push(error("M4V-E3011","DIRECT_INVARIANT","direct ineligibility invariants violated",format!("{base}/direct"),Some(&r.run_id)));
                            }
                            if x.ineligibility_reason.as_deref()==Some("PROVEN_DIRECT_BLOCKED") && (r.scenario!="T4_RESTRICTIVE_NETWORK" || x.block_evidence_ref.is_none()) {
                                d.push(error("M4V-E4002","EXCLUSION_INTEGRITY","blocked exclusion requires T4 and independent evidence reference",format!("{base}/direct/block_evidence_ref"),Some(&r.run_id)));
                            }
                            if x.ineligibility_reason.as_deref()==Some("NO_COMPATIBLE_ADDRESS_FAMILY") && r.scenario!="T5_IPV4_IPV6" {
                                d.push(error("M4V-E4006","EXCLUSION_INTEGRITY","address-family exclusion is only valid in T5",format!("{base}/direct/ineligibility_reason"),Some(&r.run_id)));
                            }
                        }
                        if x.final_decision_monotonic_ms<x.started_monotonic_ms || x.final_decision_monotonic_ms-x.started_monotonic_ms!=x.resolution_time_ms {
                            d.push(error("M4V-E5002","TIMING","direct resolution duration mismatch",format!("{base}/direct/resolution_time_ms"),Some(&r.run_id)));
                        }
                        if let Some(t)=x.connection_time_ms { if t>x.resolution_time_ms { d.push(error("M4V-E5003","TIMING","connection time exceeds resolution time",format!("{base}/direct/connection_time_ms"),Some(&r.run_id))); } }
                    }
                    None=>d.push(error("M4V-E2010","RUN_ACCOUNTING","VALID T1-T5 lacks direct attempt",format!("{base}/direct"),Some(&r.run_id)))
                }
            }
        } else if r.invalid_reason.is_none() {
            d.push(error("M4V-E2007","RUN_ACCOUNTING","INVALID run lacks invalid_reason",format!("{base}/invalid_reason"),Some(&r.run_id)));
        }
    }

    let valid_runs=manifest.runs.iter().filter(|r|r.validity=="VALID").count();
    if valid_runs!=60 {d.push(error("M4V-E2001","RUN_ACCOUNTING",format!("expected 60 VALID runs, got {valid_runs}"),"/runs",None));}
    for s in ["T1_BROADBAND_BROADBAND","T2_BROADBAND_CGNAT","T3_CGNAT_CGNAT","T4_RESTRICTIVE_NETWORK","T5_IPV4_IPV6","T6_RECONNECT"] {
        if counts.get(s).copied().unwrap_or(0)!=10 {d.push(error("M4V-E2002","RUN_ACCOUNTING",format!("{s} must contain exactly 10 VALID runs"),"/runs",None));}
    }
    if reconnect_eligible!=10 {d.push(error("M4V-E2003","RUN_ACCOUNTING",format!("expected 10 reconnect-eligible T6 runs, got {reconnect_eligible}"),"/runs",None));}

    validate_artifacts(manifest,package_root,&mut d);

    let overall=rate(direct_pass,direct_eligible);
    let cp50=percentile(connection_times.clone(),50,100); let cp95=percentile(connection_times,95,100);
    let rr=rate(reconnect_pass,reconnect_eligible);
    let rp50=percentile(reconnect_times.clone(),50,100); let rp95=percentile(reconnect_times,95,100);
    if d.iter().all(|x|x.severity!="ERROR") {
        if overall.is_some_and(|x|x<80.0){d.push(gate("M4V-G2001","overall direct success below 80%","/aggregate"));}
        for (s,threshold,code) in [("T1_BROADBAND_BROADBAND",90.0,"M4V-G2002"),("T2_BROADBAND_CGNAT",80.0,"M4V-G2003"),("T3_CGNAT_CGNAT",60.0,"M4V-G2004"),("T5_IPV4_IPV6",80.0,"M4V-G2005")] {
            let eligible=manifest.runs.iter().filter(|r|r.validity=="VALID"&&r.scenario==s&&r.direct.as_ref().is_some_and(|x|x.eligible)).count();
            let pass=manifest.runs.iter().filter(|r|r.validity=="VALID"&&r.scenario==s&&r.direct.as_ref().is_some_and(|x|x.eligible&&x.result=="PASS")).count();
            if rate(pass,eligible).is_some_and(|x|x<threshold){d.push(gate(code,format!("{s} direct success below {threshold}%"),"/aggregate"));}
        }
        if cp50.is_some_and(|x|x>1500){d.push(gate("M4V-G2101","connection P50 above 1500 ms","/aggregate"));}
        if cp95.is_some_and(|x|x>5000){d.push(gate("M4V-G2102","connection P95 above 5000 ms","/aggregate"));}
        if rr.is_some_and(|x|x<90.0){d.push(gate("M4V-G2201","reconnect success below 90%","/aggregate"));}
        if rp50.is_some_and(|x|x>2000){d.push(gate("M4V-G2202","reconnect P50 above 2000 ms","/aggregate"));}
        if rp95.is_some_and(|x|x>5000){d.push(gate("M4V-G2203","reconnect P95 above 5000 ms","/aggregate"));}
    }
    let result=if d.iter().any(|x|x.severity=="ERROR"){Outcome::InvalidManifest}else if d.iter().any(|x|x.severity=="GATE_FAIL"){Outcome::ValidM4Fail}else{Outcome::ValidM4Pass};
    Report{validator:"kmj-omnidesk-m4-validator",validator_version:"1.0.0",protocol:manifest.protocol.clone(),campaign_id:manifest.campaign_id.clone(),result,diagnostics:d,metrics:Metrics{valid_runs,direct_eligible,direct_passes:direct_pass,overall_direct_rate_percent:overall,connection_p50_ms:cp50,connection_p95_ms:cp95,reconnect_eligible,reconnect_passes:reconnect_pass,reconnect_rate_percent:rr,reconnect_p50_ms:rp50,reconnect_p95_ms:rp95}}
}

fn validate_artifacts(manifest:&Manifest,root:Option<&Path>,d:&mut Vec<Diagnostic>) {
    let mut by_id=BTreeMap::new();
    for (i,a) in manifest.artifacts.iter().enumerate() {
        if by_id.insert(a.artifact_id.as_str(),a).is_some(){d.push(error("M4V-E8001","REFERENCE_INTEGRITY","duplicate artifact_id",format!("/artifacts/{i}/artifact_id"),a.run_id.as_deref()));}
        let path=Path::new(&a.relative_path);
        if path.is_absolute() || path.components().any(|c|matches!(c,Component::ParentDir)){d.push(error("M4V-E8006","REFERENCE_INTEGRITY","artifact path escapes package",format!("/artifacts/{i}/relative_path"),a.run_id.as_deref()));}
        if let Some(root)=root {
            let full=root.join(path);
            match fs::read(&full) {
                Ok(bytes)=>{
                    if bytes.len() as u64!=a.size_bytes {d.push(error("M4V-E9002","CHECKSUM_INTEGRITY","artifact size mismatch",format!("/artifacts/{i}/size_bytes"),a.run_id.as_deref()));}
                    let actual=format!("{:x}",Sha256::digest(&bytes));
                    if actual!=a.sha256 {d.push(error("M4V-E9001","CHECKSUM_INTEGRITY","artifact SHA-256 mismatch",format!("/artifacts/{i}/sha256"),a.run_id.as_deref()));}
                }
                Err(_)=>d.push(error("M4V-E8009","REFERENCE_INTEGRITY","declared artifact missing",format!("/artifacts/{i}/relative_path"),a.run_id.as_deref()))
            }
        }
    }
    for (i,r) in manifest.runs.iter().enumerate() {
        for reference in &r.evidence_refs {
            if !by_id.contains_key(reference.as_str()){d.push(error("M4V-E8002","REFERENCE_INTEGRITY","dangling evidence reference",format!("/runs/{i}/evidence_refs"),Some(&r.run_id)));}
        }
        if let Some(reference)=r.direct.as_ref().and_then(|x|x.block_evidence_ref.as_ref()) {
            match by_id.get(reference.as_str()) {
                None=>d.push(error("M4V-E4003","EXCLUSION_INTEGRITY","block evidence reference does not resolve",format!("/runs/{i}/direct/block_evidence_ref"),Some(&r.run_id))),
                Some(a) if !matches!(a.kind.as_str(),"CONTROL_PROBE"|"NETWORK_DIAGNOSTIC")=>d.push(error("M4V-E4004","EXCLUSION_INTEGRITY","block evidence has disallowed kind",format!("/runs/{i}/direct/block_evidence_ref"),Some(&r.run_id))),
                Some(a) if a.run_id.as_deref()!=Some(&r.run_id)=>d.push(error("M4V-E8004","REFERENCE_INTEGRITY","artifact belongs to another run",format!("/runs/{i}/direct/block_evidence_ref"),Some(&r.run_id))),
                Some(_)=>{}
            }
        }
    }
}
