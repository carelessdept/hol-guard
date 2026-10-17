//! Compile authenticated policy once before publishing an immutable generation.

use super::{CompiledEffectivePolicy, PolicySnapshotV3};

/// An immutable authenticated snapshot and the selector indexes derived from
/// that exact value. No mutable dereference is exposed, so a generation cannot
/// silently retain indexes from a different effective policy.
#[derive(Debug)]
pub(crate) struct AdmittedPolicySnapshot {
    snapshot: PolicySnapshotV3,
    pub(super) compiled: CompiledEffectivePolicy,
    pub(crate) command_extensions:
        Option<guard_command::native_command_controls::CompiledNativeCommandControls>,
    pub(super) business_policy: Option<super::policy_enforcement_business::CompiledBusinessPolicy>,
}

impl AdmittedPolicySnapshot {
    pub(crate) fn new(snapshot: PolicySnapshotV3) -> Result<Self, String> {
        use crate::resident_diagnostics::{emit_elapsed, Phase};
        let started = std::time::Instant::now();
        let _ = guard_command::native_command_program::packaged_command_program_bytes();
        emit_elapsed(Phase::DiagProgramDecode, started.elapsed());
        let started = std::time::Instant::now();
        let _ = guard_command::native_command_program::packaged_command_program();
        emit_elapsed(Phase::DiagProgramParse, started.elapsed());
        let started = std::time::Instant::now();
        let compiled = CompiledEffectivePolicy::new(&snapshot.effective_policy)?;
        emit_elapsed(Phase::DiagCompileEffective, started.elapsed());
        let started = std::time::Instant::now();
        let business_policy = snapshot
            .business_policy
            .as_ref()
            .map(super::policy_enforcement_business::CompiledBusinessPolicy::new)
            .transpose()?;
        emit_elapsed(Phase::DiagCompileBusiness, started.elapsed());
        let started = std::time::Instant::now();
        let command_extensions = snapshot
            .command_extensions
            .as_ref()
            .map(guard_command::native_command_controls::CompiledNativeCommandControls::new)
            .transpose()
            .map_err(ToOwned::to_owned)?;
        emit_elapsed(Phase::DiagCompileCommand, started.elapsed());
        Ok(Self {
            snapshot,
            compiled,
            command_extensions,
            business_policy,
        })
    }

    pub(crate) fn snapshot(&self) -> &PolicySnapshotV3 {
        &self.snapshot
    }
}

impl std::ops::Deref for AdmittedPolicySnapshot {
    type Target = PolicySnapshotV3;

    fn deref(&self) -> &Self::Target {
        self.snapshot()
    }
}
