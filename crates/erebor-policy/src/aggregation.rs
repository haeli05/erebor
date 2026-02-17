use chrono::{DateTime, Duration, Utc};
use erebor_common::UserId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Types of metrics that can be aggregated
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AggregationMetric {
    TransactionCount,
    TransactionVolume { currency: String },
    UniqueRecipients,
    GasSpent,
    FailedTransactions,
}

/// Configuration for an aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Aggregation {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub metric: AggregationMetric,
    pub window: Duration,
    pub group_by: Vec<String>, // e.g. ["user_id", "chain_id"]
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// A transaction event for aggregation tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionEvent {
    pub id: Uuid,
    pub user_id: UserId,
    pub wallet_id: String,
    pub from: String,
    pub to: String,
    pub value: u128,
    pub chain_id: u64,
    pub gas_used: Option<u128>,
    pub gas_price: Option<u128>,
    pub success: bool,
    pub timestamp: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub country: Option<String>,
}

/// Data point for aggregation storage
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AggregationDataPoint {
    pub timestamp: DateTime<Utc>,
    pub value: u128,
    pub group_key: String,
}

/// In-memory store for aggregation data
#[derive(Debug, Clone)]
pub struct AggregationStore {
    aggregations: HashMap<Uuid, Aggregation>,
    data_points: HashMap<Uuid, Vec<AggregationDataPoint>>,
}

impl AggregationStore {
    /// Create a new aggregation store
    pub fn new() -> Self {
        Self {
            aggregations: HashMap::new(),
            data_points: HashMap::new(),
        }
    }

    /// Add an aggregation configuration
    pub fn add_aggregation(&mut self, aggregation: Aggregation) {
        self.data_points.insert(aggregation.id, Vec::new());
        self.aggregations.insert(aggregation.id, aggregation);
    }

    /// Remove an aggregation
    pub fn remove_aggregation(&mut self, aggregation_id: &Uuid) -> bool {
        self.data_points.remove(aggregation_id);
        self.aggregations.remove(aggregation_id).is_some()
    }

    /// Record a transaction event for all applicable aggregations
    pub fn record(&mut self, event: &TransactionEvent) {
        for (agg_id, aggregation) in &self.aggregations {
            if !aggregation.enabled {
                continue;
            }

            let group_key = self.build_group_key(aggregation, event);
            let value = self.extract_metric_value(&aggregation.metric, event);

            if let Some(data_points) = self.data_points.get_mut(agg_id) {
                data_points.push(AggregationDataPoint {
                    timestamp: event.timestamp,
                    value,
                    group_key,
                });

                // Clean up old data points outside the window
                let cutoff = Utc::now() - aggregation.window;
                data_points.retain(|dp| dp.timestamp > cutoff);
            }
        }
    }

    /// Query aggregated data for a specific aggregation and group
    pub fn query(&self, agg_id: &Uuid, group_key: &str) -> u128 {
        if let Some(aggregation) = self.aggregations.get(agg_id) {
            if let Some(data_points) = self.data_points.get(agg_id) {
                let cutoff = Utc::now() - aggregation.window;
                
                return data_points
                    .iter()
                    .filter(|dp| dp.timestamp > cutoff && dp.group_key == group_key)
                    .map(|dp| dp.value)
                    .sum();
            }
        }
        0
    }

    /// Get all aggregations
    pub fn get_aggregations(&self) -> &HashMap<Uuid, Aggregation> {
        &self.aggregations
    }

    /// Get aggregation by ID
    pub fn get_aggregation(&self, agg_id: &Uuid) -> Option<&Aggregation> {
        self.aggregations.get(agg_id)
    }

    /// Build a group key from the transaction event
    fn build_group_key(&self, aggregation: &Aggregation, event: &TransactionEvent) -> String {
        let mut key_parts = Vec::new();
        
        for field in &aggregation.group_by {
            let value = match field.as_str() {
                "user_id" => event.user_id.0.to_string(),
                "wallet_id" => event.wallet_id.clone(),
                "chain_id" => event.chain_id.to_string(),
                "to" => event.to.clone(),
                "country" => event.country.clone().unwrap_or_default(),
                _ => String::new(),
            };
            key_parts.push(value);
        }
        
        key_parts.join("|")
    }

    /// Extract metric value from transaction event
    fn extract_metric_value(&self, metric: &AggregationMetric, event: &TransactionEvent) -> u128 {
        match metric {
            AggregationMetric::TransactionCount => 1,
            AggregationMetric::TransactionVolume { .. } => event.value,
            AggregationMetric::UniqueRecipients => 1, // Will need special handling for uniqueness
            AggregationMetric::GasSpent => {
                event.gas_used.unwrap_or(0) * event.gas_price.unwrap_or(0)
            }
            AggregationMetric::FailedTransactions => {
                if event.success { 0 } else { 1 }
            }
        }
    }
}

impl Default for AggregationStore {
    fn default() -> Self {
        Self::new()
    }
}