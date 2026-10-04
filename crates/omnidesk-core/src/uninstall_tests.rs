//! U8 — uninstall residue tests.
//!
//! Every test names the single edit that would make it pass while the property
//! is broken. The ones that matter most are the negative-direction tests: a
//! suite that only ever confirms a clean uninstall passes is a suite that
//! would also pass against an uninstaller that does nothing.

use super::*;

/// A complete, ordinary uninstall: product files removed, user data kept.
fn complete_plan() -> UninstallPlan {
    let mut plan = UninstallPlan::default();
    plan.declare_root("/opt/kmj").expect("root");
    plan.record(OwnedPath::product(
        "/opt/kmj/bin/omnidesk",
        ResidueKind::InstalledBinary,
    ))
    .expect("binary");
    plan.record(OwnedPath::product(
        "/opt/kmj/updater",
        ResidueKind::UpdateScheduler,
    ))
    .expect("updater");
    plan.record(OwnedPath::product(
        "/opt/kmj/.autostart",
        ResidueKind::AutostartEntry,
    ))
    .expect("autostart");
    plan.record(OwnedPath::product(
        "/opt/kmj/entitlement.cache",
        ResidueKind::CachedSecret,
    ))
    .expect("cache");
    plan.record(OwnedPath::user_owned(
        "/opt/kmj/documents/notes.txt",
        ResidueKind::InstalledBinary,
    ))
    .expect("user data");
    plan
}

// --- the happy path, and what it preserves -------------------------------

/// Mutation: make `removal_targets` return every owned path.
#[test]
fn a_complete_uninstall_removes_every_product_file() {
    let plan = complete_plan();
    let targets = plan.removal_targets();

    assert!(targets.contains(&"/opt/kmj/bin/omnidesk"));
    assert!(targets.contains(&"/opt/kmj/updater"));
    assert!(targets.contains(&"/opt/kmj/.autostart"));
    assert!(targets.contains(&"/opt/kmj/entitlement.cache"));
    assert_eq!(targets.len(), 4, "expected exactly the four product paths");
}

/// Mutation: make `removal_targets` filter on `is_user_data()` instead of
/// `!is_user_data()`.
#[test]
fn user_data_is_kept_not_removed() {
    let plan = complete_plan();

    assert!(
        !plan
            .removal_targets()
            .contains(&"/opt/kmj/documents/notes.txt")
    );
    assert_eq!(
        plan.retained_user_data(),
        vec!["/opt/kmj/documents/notes.txt"]
    );
}

/// Mutation: return `Ok(())` from `confirm_clean` unconditionally.
#[test]
fn a_complete_uninstall_leaves_nothing_behind() {
    let plan = complete_plan();
    assert!(plan.confirm_clean(&[]).is_ok());
}

// --- the residue checks --------------------------------------------------

/// Mutation: drop the scheduler case from the `find` predicate in
/// `confirm_clean`.
#[test]
fn a_surviving_updater_is_residue() {
    let plan = complete_plan();
    let surviving = [OwnedPath::product(
        "/opt/kmj/updater",
        ResidueKind::UpdateScheduler,
    )];

    assert_eq!(
        plan.confirm_clean(&surviving),
        Err(UninstallError::ResidueRemains {
            kind: ResidueKind::UpdateScheduler,
            detail: "/opt/kmj/updater".to_string(),
        })
    );
}

/// Mutation: drop the autostart case from the `find` predicate.
#[test]
fn a_surviving_autostart_entry_is_residue() {
    let plan = complete_plan();
    let surviving = [OwnedPath::product(
        "/opt/kmj/.autostart",
        ResidueKind::AutostartEntry,
    )];

    assert_eq!(
        plan.confirm_clean(&surviving).unwrap_err(),
        UninstallError::ResidueRemains {
            kind: ResidueKind::AutostartEntry,
            detail: "/opt/kmj/.autostart".to_string(),
        }
    );
}

/// Mutation: drop the cached-secret case from the `find` predicate.
///
/// A cached entitlement outliving the application is the residue that matters
/// most: the program is gone but it still holds a licence.
#[test]
fn a_surviving_entitlement_cache_is_residue() {
    let plan = complete_plan();
    let surviving = [OwnedPath::product(
        "/opt/kmj/entitlement.cache",
        ResidueKind::CachedSecret,
    )];

    assert_eq!(
        plan.confirm_clean(&surviving).unwrap_err(),
        UninstallError::ResidueRemains {
            kind: ResidueKind::CachedSecret,
            detail: "/opt/kmj/entitlement.cache".to_string(),
        }
    );
}

// --- containment: the rule that protects user data ----------------------

/// Mutation: change `is_under` to a plain `path.starts_with(root)`.
#[test]
fn a_sibling_directory_with_a_shared_prefix_is_outside_the_root() {
    let mut plan = UninstallPlan::default();
    plan.declare_root("/opt/kmj").expect("root");

    // `/opt/kmj-backup` starts with `/opt/kmj` and is a different directory.
    assert_eq!(
        plan.record(OwnedPath::product(
            "/opt/kmj-backup/bin/omnidesk",
            ResidueKind::InstalledBinary
        )),
        Err(UninstallError::OutsideInstallRoot {
            path: "/opt/kmj-backup/bin/omnidesk".to_string(),
        })
    );
}

/// Mutation: remove the `..` check from `record`.
#[test]
fn a_traversing_path_is_refused_at_record_time() {
    let mut plan = UninstallPlan::default();
    plan.declare_root("/opt/kmj").expect("root");

    assert_eq!(
        plan.record(OwnedPath::product(
            "/opt/kmj/../../etc/passwd",
            ResidueKind::InstalledBinary
        )),
        Err(UninstallError::PathNotContained {
            path: "/opt/kmj/../../etc/passwd".to_string(),
        })
    );
}

/// Mutation: delete the containment check from `confirm_clean`'s loop.
///
/// This is the one that matters most. `confirm_clean` is the last check before
/// the product declares itself gone, and it is asked to decide about paths the
/// plan may never have recorded.
#[test]
fn confirm_clean_refuses_survival_outside_the_root() {
    let plan = complete_plan();
    let surviving = [OwnedPath::product(
        "/etc/kmj-service",
        ResidueKind::UpdateScheduler,
    )];

    assert_eq!(
        plan.confirm_clean(&surviving),
        Err(UninstallError::OutsideInstallRoot {
            path: "/etc/kmj-service".to_string(),
        })
    );
}

// --- fail-closed roots ---------------------------------------------------

/// Mutation: default `install_root` to `Some(String::new())`.
#[test]
fn a_plan_without_a_root_refuses_everything() {
    let plan = UninstallPlan::default();

    assert_eq!(plan.confirm_clean(&[]), Err(UninstallError::NoInstallRoot));
}

/// Mutation: remove the `NoInstallRoot` guard from `record`.
#[test]
fn recording_without_a_root_is_refused() {
    let mut plan = UninstallPlan::default();

    assert_eq!(
        plan.record(OwnedPath::product(
            "/opt/kmj/bin/omnidesk",
            ResidueKind::InstalledBinary
        )),
        Err(UninstallError::NoInstallRoot)
    );
}

/// Mutation: allow roots of two characters or fewer.
///
/// Note the reported string: `C:/` is refused as `C:/`, not as the trimmed
/// `C:`. The string the caller passed is the one they will find in their logs,
/// so the error names their input rather than an internal rewrite of it.
#[test]
fn a_filesystem_root_is_not_an_install_root() {
    let mut plan = UninstallPlan::default();

    assert_eq!(
        plan.declare_root("/"),
        Err(UninstallError::PathNotContained {
            path: "/".to_string()
        })
    );
    assert_eq!(
        plan.declare_root("C:"),
        Err(UninstallError::PathNotContained {
            path: "C:".to_string()
        })
    );
    assert_eq!(
        plan.declare_root("C:/"),
        Err(UninstallError::PathNotContained {
            path: "C:/".to_string()
        })
    );
}

/// Mutation: remove the `..` check from `is_plausible_root`.
#[test]
fn a_root_containing_a_traversal_is_refused() {
    let mut plan = UninstallPlan::default();

    assert!(matches!(
        plan.declare_root("/opt/../kmj"),
        Err(UninstallError::PathNotContained { .. })
    ));
}

/// Mutation: remove the length check from `declare_root`.
#[test]
fn an_absurdly_long_root_is_refused() {
    let mut plan = UninstallPlan::default();
    let long = format!("/opt/{}", "a".repeat(MAX_INSTALL_ROOT_BYTES));

    assert_eq!(
        plan.declare_root(&long),
        Err(UninstallError::InstallRootTooLong {
            length: long.len(),
            maximum: MAX_INSTALL_ROOT_BYTES,
        })
    );
}

/// Mutation: drop the trailing-slash trim from `declare_root`.
///
/// A run of separators trims down to empty, which is the filesystem root wearing
/// extra separators. It has to be refused, and it is refused by the length check
/// rather than by a normalized comparison — an earlier version also compared
/// against `"/"`, and removing that clause changed nothing, so it was removed
/// rather than kept as decoration.
#[test]
fn repeated_separators_alone_do_not_make_a_root() {
    for root in ["//", "///", "////"] {
        let mut plan = UninstallPlan::default();
        assert_eq!(
            plan.declare_root(root),
            Err(UninstallError::PathNotContained {
                path: root.to_string()
            }),
            "{root:?} is a filesystem root wearing extra separators"
        );
    }
}

/// Mutation: make `normalize` return its input unchanged.
#[test]
fn a_repeated_separator_root_normalizes_to_the_filesystem_root() {
    assert_eq!(normalize("//"), "/");
    assert_eq!(normalize("///"), "/");
}

// --- path normalization --------------------------------------------------

/// Mutation: remove the `.`-segment skip from `normalize`.
#[test]
fn dot_segments_are_normalized_before_the_containment_check() {
    let mut plan = UninstallPlan::default();
    plan.declare_root("/opt/kmj").expect("root");

    plan.record(OwnedPath::product(
        "/opt/./kmj/bin/omnidesk",
        ResidueKind::InstalledBinary,
    ))
    .expect("a path through . is the same path");
}

/// Mutation: store the trimmed-but-unnormalized root in `declare_root`.
///
/// This was a real bug, not a hypothetical one. The first version of this
/// module normalized recorded paths but stored the root raw, so the root was
/// `opt/kmj` and every child was `/opt/kmj/bin` — the two were in different
/// normal forms and *every correct path looked like it was outside its own
/// root*. It surfaced as 11 test failures, not as a silent pass, which is the
/// only reason it was caught.
#[test]
fn the_root_and_its_paths_are_compared_in_one_normal_form() {
    let mut plan = UninstallPlan::default();
    plan.declare_root("/opt/kmj").expect("root");

    assert_eq!(plan.install_root(), Some("/opt/kmj"));
    plan.record(OwnedPath::product(
        "/opt/kmj/bin/omnidesk",
        ResidueKind::InstalledBinary,
    ))
    .expect("the root contains its own children");
}

/// Mutation: drop the `trim_end_matches('/')` from `declare_root`.
#[test]
fn a_root_written_with_a_trailing_slash_still_contains_its_paths() {
    let mut plan = UninstallPlan::default();
    plan.declare_root("/opt/kmj/").expect("root");

    assert_eq!(plan.install_root(), Some("/opt/kmj"));
    plan.record(OwnedPath::product(
        "/opt/kmj/bin/omnidesk",
        ResidueKind::InstalledBinary,
    ))
    .expect("a trailing slash does not move the boundary");
}

/// Mutation: return the raw `install_root` string from the accessor.
#[test]
fn install_root_reports_the_normalized_root() {
    let mut plan = UninstallPlan::default();
    assert_eq!(plan.install_root(), None);

    plan.declare_root("/opt//kmj/./").expect("root");
    assert_eq!(plan.install_root(), Some("/opt/kmj"));
}

/// Mutation: make `normalize` resolve `..` segments.
///
/// This is the mutation the whole containment story rests on. Resolving `..`
/// turns `/opt/kmj/../../etc/passwd` into `/etc/passwd`, which is *outside* the
/// root and would be refused -- but it would be refused for the right reason by
/// accident, and a traversal that lands back inside the root would be accepted
/// on a technicality.
#[test]
fn normalize_leaves_traversal_visible_rather_than_resolving_it() {
    assert_eq!(normalize("/opt/kmj/../kmj/bin"), "/opt/kmj/../kmj/bin");
    assert!(
        normalize("/opt/kmj/../kmj/bin")
            .split('/')
            .any(|segment| segment == "..")
    );
}

/// Mutation: drop the leading-slash restoration from `normalize`.
///
/// A root of `/opt/kmj` would become `opt/kmj` and then never contain its own
/// children, so every recorded path would look outside the root.
#[test]
fn normalize_keeps_the_leading_slash_so_segments_still_align() {
    assert_eq!(normalize("/opt/kmj/bin"), "/opt/kmj/bin");
    assert_eq!(normalize("opt/kmj/bin"), "/opt/kmj/bin");
    assert!(is_under(
        &normalize("/opt/kmj"),
        &normalize("/opt/kmj/bin/x")
    ));
}

/// Mutation: change `is_under`'s `starts_with('/')` to `starts_with('.')`.
#[test]
fn the_root_itself_counts_as_under_the_root() {
    assert!(is_under("/opt/kmj", "/opt/kmj"));
    assert!(is_under("/opt/kmj", "/opt/kmj/bin/x"));
    assert!(!is_under("/opt/kmj", "/opt/kmjother"));
}

// --- the user-data distinction -------------------------------------------

/// Mutation: make `UserDataRefused` unreachable by checking user data only
/// after the residue check.
#[test]
fn a_surviving_user_data_path_is_reported_as_a_different_failure() {
    let plan = complete_plan();
    let surviving = [OwnedPath::user_owned(
        "/opt/kmj/documents/notes.txt",
        ResidueKind::InstalledBinary,
    )];

    // Residue *and* user data. The user-data failure is reported, because
    // "it survived" and "you were supposed to remove it" are different
    // problems and the second hides the first.
    assert_eq!(
        plan.confirm_clean(&surviving),
        Err(UninstallError::UserDataRefused {
            path: "/opt/kmj/documents/notes.txt".to_string(),
        })
    );
}

/// Mutation: make `OwnedPath::user_owned` set `user_data: false`.
#[test]
fn the_user_data_flag_is_what_the_two_factories_differ_in() {
    assert!(!OwnedPath::product("/a", ResidueKind::InstalledBinary).is_user_data());
    assert!(OwnedPath::user_owned("/b", ResidueKind::InstalledBinary).is_user_data());
}

/// Mutation: return `Err(ResidueRemains { kind: InstalledBinary, .. })` for
/// every surviving entry.
#[test]
fn residue_reports_which_kind_survived() {
    let plan = complete_plan();
    let surviving = [OwnedPath::product(
        "/opt/kmj/updater",
        ResidueKind::UpdateScheduler,
    )];

    match plan.confirm_clean(&surviving) {
        Err(UninstallError::ResidueRemains { kind, detail }) => {
            assert_eq!(kind, ResidueKind::UpdateScheduler);
            assert_eq!(detail, "/opt/kmj/updater");
        }
        other => panic!("expected ResidueRemains, got {other:?}"),
    }
}

/// Mutation: give every `ResidueKind` the same `name()`.
///
/// This failed to catch that mutation the first time it was run. The test
/// compared the four names to *each other*, which catches only a collapse to
/// fewer than four — swapping one name for another unique string is the edit a
/// careless rename actually makes, and it passed. Comparing each name to its
/// exact expected string catches that too.
#[test]
fn residue_kinds_have_distinct_names() {
    let expected = [
        (ResidueKind::UpdateScheduler, "update_scheduler"),
        (ResidueKind::AutostartEntry, "autostart_entry"),
        (ResidueKind::CachedSecret, "cached_secret"),
        (ResidueKind::InstalledBinary, "installed_binary"),
    ];
    for (kind, name) in expected {
        assert_eq!(kind.name(), name);
    }
}

/// Mutation: make `is_persistence` answer `false` for a variant.
///
/// The predicate has to be able to say *no*, or it cannot be a predicate. This
/// also pins the current answer deliberately rather than accidentally: today
/// every kind is persistence, and a test that asserted "all true" would keep
/// passing if someone added a genuinely safe-to-leave kind without thinking
/// about U8.
#[test]
fn every_kind_is_persistence_because_u8_has_no_safe_kind_yet() {
    for kind in [
        ResidueKind::UpdateScheduler,
        ResidueKind::AutostartEntry,
        ResidueKind::CachedSecret,
        ResidueKind::InstalledBinary,
    ] {
        assert!(kind.is_persistence(), "{kind:?} can act after uninstall");
    }
}

/// Mutation: make `Display` print a generic message for every variant.
#[test]
fn errors_name_the_rule_they_enforce() {
    let shown = UninstallError::ResidueRemains {
        kind: ResidueKind::CachedSecret,
        detail: "/opt/kmj/entitlement.cache".to_string(),
    }
    .to_string();
    assert!(shown.contains("cached_secret"), "got {shown}");
    assert!(shown.contains("/opt/kmj/entitlement.cache"), "got {shown}");

    let outside = UninstallError::OutsideInstallRoot {
        path: "/etc/kmj".to_string(),
    }
    .to_string();
    assert!(outside.contains("/etc/kmj"), "got {outside}");
}
