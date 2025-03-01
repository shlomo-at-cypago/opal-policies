package authz

import future.keywords.in

default allow = false

# Single allow rule with all conditions
allow {
    # RBAC: Admin has access to all resources
    some res in data.resources
    res.id == input.user_id
    res.role == "admin"
}

allow {
    # Editor access: Assigned entities (RBAC)
    some res in data.resources
    res.id == input.user_id
    res.role == "editor"
    some assign in data.assignments
    assign.user_id == input.user_id
    assign.entity_id == input.resource_id
}

allow {
    # Editor access: Descendants of assigned entities (ReBAC)
    some res in data.resources
    res.id == input.user_id
    res.role == "editor"
    some assign in data.assignments
    assign.user_id == input.user_id
    input.resource_id in descendants(assign.entity_id)
}

allow {
    # Auditor access: "submitted" audits under entity2 (ABAC + ReBAC)
    some res in data.resources
    res.id == input.user_id
    res.role == "auditor"
    some resource in data.resources
    resource.id == input.resource_id
    resource.status == "submitted"
    resource.type == "audit"
    input.resource_id in descendants("entity2")
}

# Helper: Compute all descendants of a parent_id as a set
descendants(parent_id) = desc_set {
    # Start with the parent itself
    initial_set := {parent_id}
    # Collect all resources
    all_resources := {res | some res in data.resources}
    # Compute transitive closure of descendants
    desc_set := graph.reachable(all_resources, initial_set)
    # Filter to only include IDs of resources that exist and are descendants
    desc_set := {res.id | some res in all_resources; res.id in desc_set}
}