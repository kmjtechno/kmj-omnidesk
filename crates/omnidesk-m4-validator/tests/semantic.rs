use omnidesk_m4_validator::{Manifest,Outcome,validate};
use serde_json::{json,Value};

fn direct() -> Value { json!({
 "eligible":true,"ineligibility_reason":null,"candidate_gathering_reached":true,
 "candidate_types":["HOST"],"candidate_pairs_attempted":1,"connected":true,"authenticated":true,
 "bidirectional_probe_passed":true,"stability_window_passed":true,"selected_candidate_type":"HOST",
 "result":"PASS","failure_code":null,"started_monotonic_ms":1000,"final_decision_monotonic_ms":2000,
 "connection_time_ms":900,"resolution_time_ms":1000,"block_evidence_ref":null
})}
fn reconnect() -> Value { json!({
 "eligible":true,"disruption_type":"PATH_LOSS","disruption_verified":true,"attempt_started":true,
 "session_restored":true,"authenticated_after_restore":true,"result":"PASS","failure_code":null,
 "disruption_detected_monotonic_ms":3000,"restored_monotonic_ms":4000,"reconnect_time_ms":1000
})}
fn manifest() -> Value {
 let sha="1111111111111111111111111111111111111111";
 let scenarios=["T1_BROADBAND_BROADBAND","T2_BROADBAND_CGNAT","T3_CGNAT_CGNAT","T4_RESTRICTIVE_NETWORK","T5_IPV4_IPV6","T6_RECONNECT"];
 let mut runs=Vec::new();
 for (si,s) in scenarios.iter().enumerate() { for n in 1..=10 {
   let t=si+1;
   runs.push(json!({
    "run_id":format!("M4-T{t}-R{n:02}"),"scenario":s,"validity":"VALID","invalid_reason":null,"build_sha":sha,
    "started_at":"2026-09-29T00:00:00Z","ended_at":"2026-09-29T00:01:00Z",
    "endpoint_a":{"anonymous_id":"a","network_class":"OTHER","ipv4_available":true,"ipv6_available":true},
    "endpoint_b":{"anonymous_id":"b","network_class":"OTHER","ipv4_available":true,"ipv6_available":true},
    "direct":if t==6 {Value::Null}else{direct()},"reconnect":if t==6 {reconnect()}else{Value::Null},"evidence_refs":[]
   }));
 }}
 json!({"schema":"kmj.omnidesk.m4.realnet-manifest","schema_version":"1.0.0","protocol":"M4-REALNET-60-v1",
  "campaign_id":"fixture-valid","build":{"git_sha":sha,"version":"fixture","artifact_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "campaign":{"started_at":"2026-09-29T00:00:00Z","ended_at":"2026-09-29T02:00:00Z","required_valid_runs":60,"required_valid_runs_per_scenario":10},
  "runs":runs,"aggregate":{},"artifacts":[],"gate":{}})
}
fn parse(v:Value)->Manifest{serde_json::from_value(v).unwrap()}

#[test] fn valid_sixty_run_fixture_passes() {
 let report=validate(&parse(manifest()),None);
 assert_eq!(report.result,Outcome::ValidM4Pass,"{:?}",report.diagnostics);
 assert_eq!(report.metrics.valid_runs,60); assert_eq!(report.metrics.direct_eligible,50);
 assert_eq!(report.metrics.direct_passes,50); assert_eq!(report.metrics.reconnect_eligible,10);
 assert_eq!(report.metrics.connection_p95_ms,Some(900)); assert_eq!(report.metrics.reconnect_p95_ms,Some(1000));
}
#[test] fn invalid_duplicate_run_is_rejected() {
 let mut v=manifest(); v["runs"][1]["run_id"]=json!("M4-T1-R01");
 let report=validate(&parse(v),None);
 assert_eq!(report.result,Outcome::InvalidManifest);
 assert!(report.diagnostics.iter().any(|x|x.code=="M4V-E2004"));
}
#[test] fn invalid_false_direct_pass_is_rejected() {
 let mut v=manifest(); v["runs"][0]["direct"]["authenticated"]=json!(false);
 let report=validate(&parse(v),None);
 assert_eq!(report.result,Outcome::InvalidManifest);
 assert!(report.diagnostics.iter().any(|x|x.code=="M4V-E3001"));
}
#[test] fn valid_evidence_can_fail_a_gate_without_becoming_invalid() {
 let mut v=manifest();
 for i in 20..25 { v["runs"][i]["direct"]["result"]=json!("FAIL"); v["runs"][i]["direct"]["connected"]=json!(false); v["runs"][i]["direct"]["authenticated"]=json!(false); v["runs"][i]["direct"]["bidirectional_probe_passed"]=json!(false); v["runs"][i]["direct"]["stability_window_passed"]=json!(false); v["runs"][i]["direct"]["connection_time_ms"]=Value::Null; v["runs"][i]["direct"]["failure_code"]=json!("NAT_NO_VIABLE_PAIR"); }
 let report=validate(&parse(v),None);
 assert_eq!(report.result,Outcome::ValidM4Fail);
 assert!(report.diagnostics.iter().any(|x|x.code=="M4V-G2004"));
}
#[test] fn invalid_reconnect_duration_is_rejected() {
 let mut v=manifest(); v["runs"][50]["reconnect"]["reconnect_time_ms"]=json!(999);
 let report=validate(&parse(v),None);
 assert_eq!(report.result,Outcome::InvalidManifest);
 assert!(report.diagnostics.iter().any(|x|x.code=="M4V-E5005"));
}
