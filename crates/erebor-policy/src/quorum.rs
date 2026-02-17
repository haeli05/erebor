use chrono::{DateTime, Utc};
use erebor_common::UserId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Roles within a quorum
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum QuorumRole {
    /// Can create/modify the quorum and approve requests
    Admin,
    /// Can approve requests
    Approver,
    /// Can view requests but not approve
    Viewer,
}

/// A member of a quorum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumMember {
    pub user_id: UserId,
    pub role: QuorumRole,
    pub added_at: DateTime<Utc>,
}

/// A key quorum for multi-party approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyQuorum {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub threshold: u32, // How many approvals needed
    pub members: Vec<QuorumMember>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Status of an approval request
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// An individual approval within a request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub user_id: UserId,
    pub approved: bool,
    pub reason: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Context for what needs approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalContext {
    pub transaction_id: Option<Uuid>,
    pub user_id: UserId,
    pub wallet_id: String,
    pub to: String,
    pub value: u128,
    pub chain_id: u64,
    pub data: Vec<u8>,
    pub ip_address: Option<String>,
    pub country: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// A request for approval from a quorum
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub quorum_id: Uuid,
    pub context: ApprovalContext,
    pub status: ApprovalStatus,
    pub approvals: Vec<Approval>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl KeyQuorum {
    /// Create a new key quorum
    pub fn new(name: String, threshold: u32) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            description: None,
            threshold,
            members: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// Add a member to the quorum
    pub fn add_member(&mut self, user_id: UserId, role: QuorumRole) -> bool {
        // Check if user is already a member
        if self.members.iter().any(|m| m.user_id == user_id) {
            return false;
        }

        self.members.push(QuorumMember {
            user_id,
            role,
            added_at: Utc::now(),
        });
        self.updated_at = Utc::now();
        true
    }

    /// Remove a member from the quorum
    pub fn remove_member(&mut self, user_id: &UserId) -> bool {
        let initial_len = self.members.len();
        self.members.retain(|m| &m.user_id != user_id);
        if self.members.len() != initial_len {
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    /// Get approvers (members who can approve)
    pub fn get_approvers(&self) -> Vec<&QuorumMember> {
        self.members
            .iter()
            .filter(|m| matches!(m.role, QuorumRole::Admin | QuorumRole::Approver))
            .collect()
    }

    /// Check if a user can approve
    pub fn can_approve(&self, user_id: &UserId) -> bool {
        self.members
            .iter()
            .any(|m| &m.user_id == user_id && matches!(m.role, QuorumRole::Admin | QuorumRole::Approver))
    }
}

impl ApprovalRequest {
    /// Create a new approval request
    pub fn new(quorum_id: Uuid, context: ApprovalContext, expires_in_hours: u32) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            quorum_id,
            context,
            status: ApprovalStatus::Pending,
            approvals: Vec::new(),
            created_at: now,
            expires_at: now + chrono::Duration::hours(expires_in_hours as i64),
        }
    }

    /// Submit an approval
    pub fn submit_approval(&mut self, user_id: UserId, approved: bool, reason: Option<String>) -> bool {
        // Check if already approved by this user
        if self.approvals.iter().any(|a| a.user_id == user_id) {
            return false;
        }

        self.approvals.push(Approval {
            user_id,
            approved,
            reason,
            timestamp: Utc::now(),
        });
        true
    }

    /// Check if the request has expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Update status based on current approvals and threshold
    pub fn update_status(&mut self, quorum: &KeyQuorum) {
        if self.is_expired() && self.status == ApprovalStatus::Pending {
            self.status = ApprovalStatus::Expired;
            return;
        }

        if self.status != ApprovalStatus::Pending {
            return;
        }

        let approvals = self.approvals.iter().filter(|a| a.approved).count() as u32;
        let denials = self.approvals.iter().filter(|a| !a.approved).count() as u32;
        
        // Check if we have enough approvals
        if approvals >= quorum.threshold {
            self.status = ApprovalStatus::Approved;
        }
        // Check if we can never reach threshold (more denials than possible)
        else if denials > (quorum.get_approvers().len() as u32 - quorum.threshold) {
            self.status = ApprovalStatus::Denied;
        }
    }
}

/// Store for managing approval requests
#[derive(Debug, Clone)]
pub struct ApprovalStore {
    requests: HashMap<Uuid, ApprovalRequest>,
}

impl ApprovalStore {
    /// Create a new approval store
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
        }
    }

    /// Add an approval request
    pub fn add_request(&mut self, request: ApprovalRequest) {
        self.requests.insert(request.id, request);
    }

    /// Get an approval request
    pub fn get_request(&self, request_id: &Uuid) -> Option<&ApprovalRequest> {
        self.requests.get(request_id)
    }

    /// Get a mutable approval request
    pub fn get_request_mut(&mut self, request_id: &Uuid) -> Option<&mut ApprovalRequest> {
        self.requests.get_mut(request_id)
    }

    /// Get all pending requests for a quorum
    pub fn get_pending_requests_for_quorum(&self, quorum_id: &Uuid) -> Vec<&ApprovalRequest> {
        self.requests
            .values()
            .filter(|r| r.quorum_id == *quorum_id && r.status == ApprovalStatus::Pending)
            .collect()
    }

    /// Remove expired requests
    pub fn cleanup_expired(&mut self) {
        self.requests.retain(|_, req| !req.is_expired() || req.status != ApprovalStatus::Pending);
    }
}

impl Default for ApprovalStore {
    fn default() -> Self {
        Self::new()
    }
}