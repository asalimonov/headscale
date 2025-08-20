#!/bin/sh
set -e

# Function to update user and group IDs
update_user_group() {
    local target_uid="${PUID:-1000}"
    local target_gid="${PGID:-1000}"
    
    echo "Starting with UID: $target_uid, GID: $target_gid"
    
    # Update group ID if different
    if [ "$(id -g headscale 2>/dev/null)" != "$target_gid" ]; then
        echo "Updating headscale group to GID: $target_gid"
        groupmod -g "$target_gid" headscale
    fi
    
    # Update user ID if different
    if [ "$(id -u headscale 2>/dev/null)" != "$target_uid" ]; then
        echo "Updating headscale user to UID: $target_uid"
        usermod -u "$target_uid" headscale
    fi
}

# Function to fix permissions
fix_permissions() {
    echo "Fixing permissions..."
    chown -R headscale:headscale /etc/headscale || true
    chown -R headscale:headscale /var/lib/headscale || true
    chown -R headscale:headscale /var/run/headscale || true
    chown -R headscale:headscale /data || true
}

# Update user and group IDs
update_user_group

# Fix permissions
fix_permissions

# Handle environment variables that start with HEADSCALE_
# These will override config file settings
export_headscale_vars() {
    for var in $(env | grep '^HEADSCALE_' | cut -d= -f1); do
        export "$var"
    done
}

export_headscale_vars

# If running as root, switch to headscale user
if [ "$(id -u)" = "0" ]; then
    echo "Running as headscale user..."
    exec su-exec headscale:headscale /usr/local/bin/headscale "$@"
else
    exec /usr/local/bin/headscale "$@"
fi