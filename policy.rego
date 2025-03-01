package rbac

# Default deny unless explicitly allowed
default allow = false

# Allow if the user has a role that permits the action on the resource
allow {
    # Get the user's roles from input
    user_roles := data.users[input.user]
    
    # Check each role the user has
    some role
    role := user_roles[_]
    
    # Check permissions for that role
    some permission
    permission := data.roles[role][_]
    
    # Match the input action and resource
    permission.action == input.action
    permission.resource == input.resource
}

# Special case for wildcard resource ("*")
allow {
    user_roles := data.users[input.user]
    some role
    role := user_roles[_]
    some permission
    permission := data.roles[role][_]
    permission.action == input.action
    permission.resource == "*"
}