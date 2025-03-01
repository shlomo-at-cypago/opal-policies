package auth

default allow = false

allow {
    input.user.role == "admin"
    input.request.tenant_id == input.user.tenant_id
    input.request.resource == "entity"
}

allow {
    input.user.role == "editor"
    input.request.tenant_id == input.user.tenant_id
    input.request.resource == "entity"
    some i
    input.user.assigned_entities[i] == input.request.entity_id
}