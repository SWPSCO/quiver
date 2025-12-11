use nockchain_libp2p_io::tip5_util::tip5_hash_to_base58;
use serde::{Deserialize, Serialize};
use bytes::Bytes;
use nockapp::noun::slab::NounSlab;
use uuid::Uuid;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AccountInformation {
    pub user_uuid: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Target {
    Network,
    Pool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Template {
    pub version: Bytes,
    pub commit: Bytes,
    pub network_target: Bytes,
    pub pool_target: Bytes,
    pub pow_len: Bytes,
}
impl Template {
    pub fn new(version: Bytes, commit: Bytes, network_target: Bytes, pool_target: Bytes, pow_len: Bytes) -> Self {
        Self {version, commit, network_target, pool_target, pow_len}
    }
    pub fn commit_as_base58(&self) -> Result<String, anyhow::Error> {
        let mut slab: NounSlab = NounSlab::new();
        let commit = slab.cue_into(self.commit.clone().into()).map_err(|_| anyhow::anyhow!("Failed to cue commit"))?;
        tip5_hash_to_base58(commit).map_err(|_| anyhow::anyhow!("Failed to convert commit to base58"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TemplateInternal {
    pub version: Bytes,
    pub commit: Bytes,
    pub network_target: Bytes,
    pub pool_target: Bytes,
    pub candidate_height: u32,
    pub pow_len: Bytes,
}

impl TemplateInternal {
    pub fn new(
        version: Bytes,
        commit: Bytes,
        network_target: Bytes,
        pool_target: Bytes,
        candidate_height: u32,
        pow_len: Bytes,
    ) -> Self {
        Self {version, commit, network_target, pool_target, candidate_height, pow_len}
    }
    pub fn commit_as_base58(&self) -> Result<String, anyhow::Error> {
        let mut slab: NounSlab = NounSlab::new();
        let commit = slab.cue_into(self.commit.clone().into()).map_err(|_| anyhow::anyhow!("Failed to cue commit"))?;
        tip5_hash_to_base58(commit).map_err(|_| anyhow::anyhow!("Failed to convert commit to base58"))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Submission {
    pub target_type: Target,
    pub commit: Bytes,
    pub digest: Bytes,
    pub proof: Bytes,

}

impl Submission {
    pub fn new(target_type: Target, commit: Bytes, digest: Bytes, proof: Bytes) -> Self {
        Self { target_type, commit, digest, proof }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SubmissionResponse {
    pub accepted: bool,
    pub digest: Bytes,
    pub message: String,
}

impl SubmissionResponse {
    pub fn new(accepted: bool, digest: Bytes, message: String) -> Self {
        Self { accepted, digest, message }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnnouncementResponse {
    pub accepted: bool,
    pub digest: Bytes,
    pub coins: u64,
    pub message: String,
}

impl AnnouncementResponse {
    pub fn new(accepted: bool, digest: Bytes, coins: u64, message: String) -> Self {
        Self { accepted, digest, coins, message }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Announcement {
    pub commit: Bytes,
    pub digest: Bytes,
    pub proof: Bytes,
    pub candidate_height: u32,
}

impl Announcement {
    pub fn new(commit: Bytes, digest: Bytes, proof: Bytes, candidate_height: u32) -> Self {
        Self { commit, digest, proof, candidate_height }
    }
}
