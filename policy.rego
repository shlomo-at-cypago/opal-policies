package authz

import future.keywords.in

default allow = false

# RBAC: Admin has access to all resources
allow if {
    some res in data.resources
    res.id == input.user_id
    res.role == "admin"
}

# Editor access: Assigned entities and their descendants (RBAC + ReBAC)
allow if {
    some res in data.resources
    res.id == input.user_id
    res.role == "editor"
    some assign in data.assignments
    assign.user_id == input.user_id
    assigned_entity_id := assign.entity_id
    requested_entity_id := input.resource_id
    
    # Direct assignment
    assigned_entity_id == requested_entity_id
}

allow if {
    some res in data.resources
    res.id == input.user_id
    res.role == "editor"
    some assign in data.assignments
    assign.user_id == input.user_id
    assigned_entity_id := assign.entity_id
    
    # ReBAC: Access to descendants of assigned entity
    is_descendant_of(assigned_entity_id, input.resource_id)
}

# Auditor access: "submitted" audits under a specific entity (ABAC + ReBAC)
allow if {
    some res in data.resources
    res.id == input.user_id
    res.role == "auditor"
    some resource in data.resources
    resource.id == input.resource_id
    resource.status == "submitted"
    resource.type == "audit"
    # Restrict to audits under entity2 (example specific entity)
    is_descendant_of("entity2", input.resource_id)
}

# Helper: Check if resource_id is a descendant of parent_id (recursive)
# Base case: Direct parent match
is_descendant_of(parent_id, resource_id) if {
    some res in data.resources
    res.id == resource_id
    res.parent_id == parent_id
}

# Recursive case: Traverse up the hierarchy
is_descendant_of(parent_id, resource_id) if {
    some res in data.resources
    res.id == resource_id
    res.parent_id != null  # Ensure we don’t recurse infinitely on null parents
    is_descendant_of(parent_id, res.parent_id)
}