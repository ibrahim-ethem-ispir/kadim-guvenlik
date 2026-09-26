use crate::AppState;
use crate::models::entity::Entity;
use crate::api::responses::GraphData;
use std::sync::Arc;
use anyhow::Result;

pub async fn run_transform(_state: &Arc<AppState>, _entity: &Entity, _transform_type: &str) -> Result<GraphData> {
    // Placeholder stub
    Ok(GraphData {
        nodes: vec![],
        edges: vec![],
        stats: crate::api::responses::GraphStats {
            total_nodes: 0,
            total_edges: 0,
            node_types: serde_json::Value::Null,
            edge_types: serde_json::Value::Null,
        },
    })
}
