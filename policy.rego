package authz

default allow = false

allow {
  input.tenant_id == some tenant_id
  input.action == "read"
  "read" in data.tenants[tenant_id].roles[input.role]
}
