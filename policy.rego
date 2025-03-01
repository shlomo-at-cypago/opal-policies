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
    is_descendant_of(assign.entity_id, input.resource_id)
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
    is_descendant_of("entity2", input.resource_id)
}

# Helper: Check if resource_id is a descendant of parent_id (recursive)
is_descendant_of(parent_id, resource_id) {
    some res in data.resources
    res.id == resource_id
    res.parent_id == parent_id
}

is_descendant_of(parent_id, resource_id) {
    some res in data.resources
    res.id == resource_id
    res.parent_id != null
    is_descendant_of(parent_id, res.parent_id)
}