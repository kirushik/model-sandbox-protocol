//! System requirements validation.
//!
//! This module provides functions to check that the host system meets
//! all requirements for running the sandbox.

mod requirements;

pub use requirements::{
    MIN_KERNEL_VERSION, MIN_LANDLOCK_ABI, SystemRequirements, check_all, check_architecture,
    check_cgroups_v2, check_kernel_version, check_landlock_abi, check_user_namespaces,
};
