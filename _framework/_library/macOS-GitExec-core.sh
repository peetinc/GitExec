#!/bin/bash
################################################################################
# macOS-GitExec-core.sh
#
# Core library for GitExec framework
# Contains all business logic, functions, and execution code
# This file is downloaded and sourced by the thin wrapper script
#
# Copyright (C) 2026 Peet, Inc.
# Licensed under GPLv2
################################################################################

# ====== ENTRY POINT ======
gitexec_init() {
    # First normalize any boolean variables from RMM
    normalize_boolean_variables
    
    # Build scriptUrl from components if provided
    if [[ -n "$scriptUrlBase" ]] && [[ -n "$scriptName" ]]; then
        scriptUrlBase="${scriptUrlBase%/}"
        scriptName="${scriptName#/}"
        scriptUrl="${scriptUrlBase}/${scriptName}"
    elif [[ -n "$scriptUrlBase" ]] || [[ -n "$scriptName" ]]; then
        log_message ERROR "Both scriptUrlBase and scriptName are required when using URL components"
        log_message ERROR "scriptUrlBase: ${scriptUrlBase:-(not set)}"
        log_message ERROR "scriptName: ${scriptName:-(not set)}"
        exit 1
    fi

    # Validate required variables
    if [[ -z "$scriptUrl" ]]; then
        log_message ERROR "scriptUrl is required but not set"
        log_message ERROR "Set scriptUrl or both scriptUrlBase and scriptName"
        exit 1
    fi

    # SECURITY: Require HTTPS to prevent man-in-the-middle attacks
    if [[ ! "$scriptUrl" =~ ^https:// ]]; then
        log_message ERROR "scriptUrl must use HTTPS protocol"
        log_message ERROR "Provided URL: $scriptUrl"
        log_message ERROR "HTTP URLs are not allowed for security reasons"
        exit 1
    fi

    # Set defaults
    runAsUser="${runAsUser:-false}"
    useAPI="${useAPI:-false}"
    runAsUserTimeout="${runAsUserTimeout:-600}"

    # Logging defaults
    loggingMode="${loggingMode:-Full}"
    logRetentionDays="${logRetentionDays:-30}"

    # Validate loggingMode
    if [[ "$loggingMode" != "None" ]] && [[ "$loggingMode" != "FrameworkOnly" ]] && [[ "$loggingMode" != "Full" ]]; then
        log_message WARN "Invalid loggingMode '$loggingMode', defaulting to 'Full'"
        loggingMode="Full"
    fi

    # Run main execution
    gitexec_main
}

# ====== NORMALIZE BOOLEAN VARIABLES ======
normalize_boolean_variables() {
    local var_names=$(compgen -v)

    for var_name in $var_names; do
        # Skip readonly/special variables
        if [[ "$var_name" =~ ^(BASH|EUID|UID|PPID|RANDOM|SECONDS|LINENO|OLDPWD|PWD|SHLVL|_).*$ ]]; then
            continue
        fi

        # Skip our constants
        if [[ "$var_name" =~ ^(PROJECT_|KEYCHAIN_|BASE_DIR|DEVICE_DIR|USER_DIR|scriptUrl)$ ]]; then
            continue
        fi

        # Additional validation: only allow alphanumeric variable names
        if [[ ! "$var_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
            continue
        fi

        local var_value="${!var_name}"

        # Convert to lowercase (bash 3.x compatible)
        local var_value_lower=$(echo "$var_value" | tr '[:upper:]' '[:lower:]')

        # SECURITY: Use printf -v for indirect assignment instead of eval
        if [[ "$var_value_lower" =~ ^(\$?true|yes)$ ]]; then
            printf -v "$var_name" '%s' 'true'
        elif [[ "$var_value_lower" =~ ^(\$?false|no)$ ]]; then
            printf -v "$var_name" '%s' 'false'
        fi
    done
}

# ====== CONFIGURATION ======
PROJECT_NAME="GitExec"
PROJECT_VERSION="1.0.1"

# ====== CONSTANTS ======
KEYCHAIN_SERVICE_PAT="com.gitexec.github-pat"
KEYCHAIN_ACCOUNT_PAT="gitexec_pat"
KEYCHAIN_SERVICE_RSA="com.gitexec.rsa-public-key"
KEYCHAIN_ACCOUNT_RSA="gitexec_rsa_pub"
BASE_DIR="/Library/Application Support/GitExec"
DEVICE_DIR="$BASE_DIR/Device"
USER_DIR="$BASE_DIR/User"
LOG_DIR_SYSTEM="$BASE_DIR/Logs/System"
LOG_DIR_USER="$BASE_DIR/Logs/User"
LOG_DIR_TEMP="$BASE_DIR/Logs/Temp"

# Detect if colors should be used
if [[ -t 1 ]] && [[ -n "${TERM}" ]] && [[ "${TERM}" != "dumb" ]]; then
    USE_COLORS=true
else
    USE_COLORS=false
fi

# Color codes (only if supported)
if [[ "$USE_COLORS" == true ]]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    NC='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    CYAN=''
    NC=''
fi

################################################################################
# LOG DIRECTORY SETUP FUNCTIONS
################################################################################

ensure_log_directories() {
    [[ "$loggingMode" == "None" ]] && return 0

    # Create System log directory
    if [[ ! -d "$LOG_DIR_SYSTEM" ]]; then
        mkdir -p "$LOG_DIR_SYSTEM"
        chown root:admin "$LOG_DIR_SYSTEM"
        chmod 770 "$LOG_DIR_SYSTEM"  # root:admin only, no user access
    fi

    # Create User log directory
    if [[ ! -d "$LOG_DIR_USER" ]]; then
        mkdir -p "$LOG_DIR_USER"
        chown root:admin "$LOG_DIR_USER"
        chmod 770 "$LOG_DIR_USER"  # root:admin only, no user access
    fi

    # Create Temp log directory
    if [[ ! -d "$LOG_DIR_TEMP" ]]; then
        mkdir -p "$LOG_DIR_TEMP"
        chown root:admin "$LOG_DIR_TEMP"
        chmod 1777 "$LOG_DIR_TEMP"  # Sticky bit: users can write, only owner can delete
    fi
}

cleanup_old_logs() {
    [[ "$loggingMode" == "None" ]] && return 0
    [[ "$logRetentionDays" -le 0 ]] && return 0

    # Cleanup System logs
    if [[ -d "$LOG_DIR_SYSTEM" ]]; then
        find "$LOG_DIR_SYSTEM" -name "*.log" -type f -mtime +"$logRetentionDays" -delete 2>/dev/null || true
    fi

    # Cleanup User logs
    if [[ -d "$LOG_DIR_USER" ]]; then
        find "$LOG_DIR_USER" -name "*.log" -type f -mtime +"$logRetentionDays" -delete 2>/dev/null || true
    fi
}

cleanup_temp_logs() {
    # Sweep temp folder for orphaned *.output.log files
    if [[ -d "$LOG_DIR_TEMP" ]]; then
        find "$LOG_DIR_TEMP" -name "*.output.log" -type f -delete 2>/dev/null || true
    fi
}

################################################################################
# LOGGING FUNCTIONS
################################################################################

log_message() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    
    case "$level" in
        START)
            echo -e "${CYAN}[$timestamp] [START] $message${NC}" >&2
            ;;
        COMPLETE)
            echo -e "${CYAN}[$timestamp] [COMPLETE] $message${NC}" >&2
            ;;
        INFO)
            echo "[$timestamp] [INFO] $message" >&2
            ;;
        OK)
            echo -e "${GREEN}[$timestamp] [OK] $message${NC}" >&2
            ;;
        WARN)
            echo -e "${YELLOW}[$timestamp] [WARN] $message${NC}" >&2
            ;;
        ERROR)
            echo -e "${RED}[$timestamp] [ERROR] $message${NC}" >&2
            ;;
        *)
            echo "[$timestamp] $message" >&2
            ;;
    esac
}

################################################################################
# HELPER FUNCTIONS
################################################################################

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_message ERROR "$PROJECT_NAME must be run as root"
        exit 1
    fi
}

get_github_pat() {
    local pat
    pat=$(security find-generic-password -s "$KEYCHAIN_SERVICE_PAT" -a "$KEYCHAIN_ACCOUNT_PAT" -w /Library/Keychains/System.keychain 2>/dev/null)
    
    if [[ $? -ne 0 ]] || [[ -z "$pat" ]]; then
        log_message ERROR "No stored PAT found in system keychain"
        log_message ERROR "Service: $KEYCHAIN_SERVICE_PAT"
        log_message ERROR "Account: $KEYCHAIN_ACCOUNT_PAT"
        log_message ERROR "Run macOS-set-gitexec_secrets.sh first to configure authentication"
        exit 1
    fi
    
    echo "$pat"
}

get_logged_in_users() {
    local users=()
    
    # Get console user
    local console_user
    console_user=$(stat -f '%Su' /dev/console 2>/dev/null)
    if [[ -n "$console_user" ]] && [[ "$console_user" != "root" ]] && [[ "$console_user" != "_windowserver" ]]; then
        users+=("$console_user")
    fi
    
    # Get users with loginwindow processes (GUI sessions)
    while IFS= read -r user; do
        if [[ -n "$user" ]] && [[ "$user" != "root" ]] && [[ ! " ${users[@]} " =~ " $user " ]]; then
            users+=("$user")
        fi
    done < <(ps -axo user,comm | grep -i 'loginwindow' | awk '{print $1}' | sort -u)
    
    printf '%s\n' "${users[@]}"
}

convert_github_url_to_raw() {
    local url="$1"
    
    # If already raw URL, return as-is
    if [[ "$url" =~ ^https://raw\.githubusercontent\.com/ ]]; then
        echo "$url"
        return 0
    fi
    
    # Convert github.com/owner/repo/blob/branch/path to raw format
    if [[ "$url" =~ ^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$ ]]; then
        local owner="${BASH_REMATCH[1]}"
        local repo="${BASH_REMATCH[2]}"
        local branch="${BASH_REMATCH[3]}"
        local path="${BASH_REMATCH[4]}"
        echo "https://raw.githubusercontent.com/$owner/$repo/$branch/$path"
        return 0
    fi
    
    log_message ERROR "Invalid GitHub URL format: $url"
    exit 1
}

convert_github_url_to_api() {
    local url="$1"
    
    # Convert github.com/owner/repo/blob/branch/path to API format
    if [[ "$url" =~ ^https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.+)$ ]]; then
        local owner="${BASH_REMATCH[1]}"
        local repo="${BASH_REMATCH[2]}"
        local path="${BASH_REMATCH[4]}"
        echo "https://api.github.com/repos/$owner/$repo/contents/$path"
        return 0
    fi
    
    log_message ERROR "Invalid GitHub URL format for API: $url"
    exit 1
}

verify_script_signature() {
    local script_path="$1"
    local sig_path="${script_path}.sig"
    
    log_message INFO "Verifying script signature..."
    
    # Check if signature file exists
    if [[ ! -f "$sig_path" ]]; then
        log_message ERROR "Signature file not found: $sig_path"
        log_message ERROR "Cannot verify script integrity"
        return 1
    fi
    
    # Retrieve public key from keychain
    log_message INFO "Retrieving RSA public key from keychain..."
    local base64_key
    base64_key=$(security find-generic-password -s "$KEYCHAIN_SERVICE_RSA" -a "$KEYCHAIN_ACCOUNT_RSA" -w /Library/Keychains/System.keychain 2>/dev/null)
    
    if [[ $? -ne 0 ]] || [[ -z "$base64_key" ]]; then
        log_message ERROR "No RSA public key found in system keychain"
        log_message ERROR "Service: $KEYCHAIN_SERVICE_RSA"
        log_message ERROR "Account: $KEYCHAIN_ACCOUNT_RSA"
        log_message ERROR "Run macOS-set-gitexec_secrets.sh first to configure"
        return 1
    fi
    
    log_message OK "RSA public key retrieved and formatted"
    
    # Verify signature using process substitution (no temp file!)
    if openssl dgst -sha256 -verify <(
        echo "-----BEGIN PUBLIC KEY-----"
        echo "$base64_key" | fold -w 64
        echo "-----END PUBLIC KEY-----"
    ) -signature "$sig_path" "$script_path" &>/dev/null; then
        log_message OK "Signature verification PASSED"
        log_message OK "Script integrity confirmed"
        return 0
    else
        log_message ERROR "Signature verification FAILED"
        log_message ERROR "Script may be tampered with or signature invalid"
        log_message ERROR "REFUSING TO EXECUTE"
        return 1
    fi
}

################################################################################
# DOWNLOAD FUNCTION
################################################################################

ensure_directory() {
    local dir_path="$1"
    local permissions="$2"
    
    if [[ ! -d "$dir_path" ]]; then
        mkdir -p "$dir_path"
        chown root:admin "$dir_path"
        chmod "$permissions" "$dir_path"
        log_message INFO "Created directory: $dir_path (permissions: $permissions)"
    fi
}

download_payload_script() {
    local remote_url="$1"
    local github_pat="$2"
    local run_as_user="$3"
    
    # Determine which directory to use based on execution mode
    local temp_dir
    local permissions
    if [[ "$run_as_user" == "true" ]]; then
        temp_dir="$USER_DIR"
        permissions="755"
    else
        temp_dir="$DEVICE_DIR"
        permissions="770"
    fi
    
    # Ensure directory exists with proper permissions
    ensure_directory "$temp_dir" "$permissions"
    
    # Clean up old scripts (older than 1 hour)
    find "$temp_dir" -name "*.sh" -type f -mmin +60 -delete 2>/dev/null
    find "$temp_dir" -name "*.sig" -type f -mmin +60 -delete 2>/dev/null
    
    # Generate unique filename
    local uuid=$(uuidgen | tr '[:upper:]' '[:lower:]')
    local download_path="$temp_dir/${uuid}.sh"
    local sig_path="${download_path}.sig"
    
    # Construct signature URL by injecting _sig/ into the path
    local sig_url
    if [[ "$remote_url" == *"api.github.com"* ]]; then
        sig_url="${remote_url/\/contents\///contents/_sig/}.sig"
    else
        if [[ "$remote_url" =~ ^(https://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/)(.+)$ ]]; then
            local base="${BASH_REMATCH[1]}"
            local path="${BASH_REMATCH[2]}"
            sig_url="${base}_sig/${path}.sig"
        else
            log_message ERROR "Unable to parse URL for signature: $remote_url"
            return 1
        fi
    fi
    
    # Download script
    log_message INFO "Script URL: $remote_url"
    if [[ "$remote_url" == *"api.github.com"* ]]; then
        log_message INFO "Downloading from GitHub API (cache-bypass)"
        
        if ! curl -sSL \
            -H "Authorization: Bearer $github_pat" \
            -H "Accept: application/vnd.github.v3.raw" \
            -H "User-Agent: $PROJECT_NAME/$PROJECT_VERSION" \
            -o "$download_path" \
            "$remote_url"; then
            log_message ERROR "Script download failed from API"
            return 1
        fi
    else
        log_message INFO "Downloading script"
        
        if ! curl -sSL \
            -H "Authorization: Bearer $github_pat" \
            -H "User-Agent: $PROJECT_NAME/$PROJECT_VERSION" \
            -o "$download_path" \
            "$remote_url"; then
            log_message ERROR "Script download failed"
            return 1
        fi
    fi
    
    # Download signature
    log_message INFO "Signature URL: $sig_url"
    log_message INFO "Downloading signature"

    if [[ "$remote_url" == *"api.github.com"* ]]; then
        if ! curl -sSL \
            -H "Authorization: Bearer $github_pat" \
            -H "Accept: application/vnd.github.v3.raw" \
            -H "User-Agent: $PROJECT_NAME/$PROJECT_VERSION" \
            -o "$sig_path" \
            "$sig_url"; then
            log_message ERROR "Signature download failed"
            rm -f "$download_path"
            return 1
        fi
    else
        if ! curl -sSL \
            -H "Authorization: Bearer $github_pat" \
            -H "User-Agent: $PROJECT_NAME/$PROJECT_VERSION" \
            -o "$sig_path" \
            "$sig_url"; then
            log_message ERROR "Signature download failed"
            rm -f "$download_path"
            return 1
        fi
    fi
    
    # Make executable
    chmod +x "$download_path"
    
    log_message OK "Downloaded to: $download_path"
    log_message OK "Downloaded signature to: $sig_path"
    echo "$download_path"
    return 0
}

################################################################################
# EXECUTION FUNCTIONS
################################################################################

execute_script_as_root() {
    local script_path="$1"
    local timestamp="$2"
    local script_name="$3"

    log_message INFO "Executing $script_name as root"
    echo "============================================="
    echo "     $PROJECT_NAME v$PROJECT_VERSION"
    echo "     SCRIPT: $script_name"
    echo "============================================="
    echo "============BEGIN SCRIPT OUTPUT============="

    local exit_code=0

    # If Full logging mode, capture output to dedicated file
    if [[ "$loggingMode" == "Full" ]]; then
        local output_log="$LOG_DIR_SYSTEM/${timestamp}_${script_name}.output.log"

        # Execute with output redirection (captures all streams)
        bash "$script_path" > "$output_log" 2>&1
        exit_code=$?

        # Display captured output
        if [[ -f "$output_log" ]]; then
            cat "$output_log"
        fi
    else
        # FrameworkOnly or None - just run and display
        bash "$script_path"
        exit_code=$?
    fi

    echo "=============END SCRIPT OUTPUT=============="
    log_message INFO "Script completed with exit code: $exit_code"

    return $exit_code
}

execute_script_as_users() {
    local timestamp="$1"
    local script_name="$2"

    # Get all logged-in users (bash 3.x compatible)
    local users=()
    while IFS= read -r user; do
        [[ -n "$user" ]] && users+=("$user")
    done < <(get_logged_in_users)
    
    if [[ ${#users[@]} -eq 0 ]]; then
        log_message ERROR "runAsUser=true but no interactive users are logged in"
        exit 1
    fi
    
    log_message INFO "Found ${#users[@]} logged-in user(s): ${users[*]}"
    
    # Get credentials once
    local github_pat
    github_pat=$(get_github_pat)
    
    # Convert URL once
    local remote_url
    if [[ "$useAPI" == "true" ]]; then
        log_message INFO "Using GitHub API (cache-bypass mode)"
        remote_url=$(convert_github_url_to_api "$scriptUrl")
    else
        log_message INFO "Converting GitHub URL to raw format"
        remote_url=$(convert_github_url_to_raw "$scriptUrl")
    fi
    
    # Construct signature URL once
    local sig_url
    if [[ "$remote_url" == *"api.github.com"* ]]; then
        sig_url="${remote_url/\/contents\///contents/_sig/}.sig"
    else
        if [[ "$remote_url" =~ ^(https://raw\.githubusercontent\.com/[^/]+/[^/]+/[^/]+/)(.+)$ ]]; then
            local base="${BASH_REMATCH[1]}"
            local path="${BASH_REMATCH[2]}"
            sig_url="${base}_sig/${path}.sig"
        else
            log_message ERROR "Unable to parse URL for signature"
            exit 1
        fi
    fi

    log_message INFO "Script URL: $remote_url"
    log_message INFO "Signature URL: $sig_url"

    local -a pids=()
    local -a user_list=()
    local -a user_script_paths=()
    local -a temp_log_paths=()

    # Launch script for each user
    for user in "${users[@]}"; do
        log_message INFO "Setting up execution environment for user: $user"
        
        # Create user-specific directory with 700 permissions
        local user_dir="$USER_DIR/$user"
        if [[ ! -d "$user_dir" ]]; then
            mkdir -p "$user_dir"
            chown "$user:staff" "$user_dir"
            chmod 700 "$user_dir"
            log_message INFO "Created secure directory: $user_dir (700, owner: $user)"
        fi
        
        # Clean up old files in user's directory (older than 1 hour)
        find "$user_dir" -name "*.sh" -type f -mmin +60 -delete 2>/dev/null
        find "$user_dir" -name "*.sig" -type f -mmin +60 -delete 2>/dev/null
        
        # Generate unique filenames for this user
        local uuid=$(uuidgen | tr '[:upper:]' '[:lower:]')
        local user_script_path="$user_dir/${uuid}.sh"
        local user_sig_path="${user_script_path}.sig"
        
        # Download script for this user
        log_message INFO "Downloading script for $user"
        if [[ "$remote_url" == *"api.github.com"* ]]; then
            if ! curl -sSL \
                -H "Authorization: Bearer $github_pat" \
                -H "Accept: application/vnd.github.v3.raw" \
                -H "User-Agent: $PROJECT_NAME/$PROJECT_VERSION" \
                -o "$user_script_path" \
                "$remote_url"; then
                log_message ERROR "Script download failed for $user"
                continue
            fi
        else
            if ! curl -sSL \
                -H "Authorization: Bearer $github_pat" \
                -H "User-Agent: $PROJECT_NAME/$PROJECT_VERSION" \
                -o "$user_script_path" \
                "$remote_url"; then
                log_message ERROR "Script download failed for $user"
                continue
            fi
        fi
        
        # Download signature for this user
        if [[ "$remote_url" == *"api.github.com"* ]]; then
            if ! curl -sSL \
                -H "Authorization: Bearer $github_pat" \
                -H "Accept: application/vnd.github.v3.raw" \
                -H "User-Agent: $PROJECT_NAME/$PROJECT_VERSION" \
                -o "$user_sig_path" \
                "$sig_url"; then
                log_message ERROR "Signature download failed for $user"
                rm -f "$user_script_path"
                continue
            fi
        else
            if ! curl -sSL \
                -H "Authorization: Bearer $github_pat" \
                -H "User-Agent: $PROJECT_NAME/$PROJECT_VERSION" \
                -o "$user_sig_path" \
                "$sig_url"; then
                log_message ERROR "Signature download failed for $user"
                rm -f "$user_script_path"
                continue
            fi
        fi
        
        # Set ownership and permissions
        chown "$user:staff" "$user_script_path" "$user_sig_path"
        chmod 700 "$user_script_path"
        chmod 600 "$user_sig_path"
        
        log_message OK "Downloaded script for $user: $user_script_path"
        
        # Verify signature before execution
        log_message INFO "Verifying signature for $user..."
        if ! verify_script_signature "$user_script_path"; then
            log_message ERROR "Signature verification failed for $user - skipping execution"
            rm -f "$user_script_path" "$user_sig_path"
            continue
        fi
        
        log_message OK "Signature verified for $user"

        # Generate temp log path if Full logging mode
        local temp_log=""
        if [[ "$loggingMode" == "Full" ]]; then
            local temp_log_uuid=$(uuidgen | tr '[:upper:]' '[:lower:]')
            temp_log="$LOG_DIR_TEMP/${temp_log_uuid}.output.log"
        fi

        # Create wrapper script in user's directory
        local wrapper_uuid=$(uuidgen | tr '[:upper:]' '[:lower:]')
        local wrapper_script="$user_dir/wrapper_${wrapper_uuid}.sh"

        if [[ "$loggingMode" == "Full" ]]; then
            # Wrapper with output redirection to temp log
            cat > "$wrapper_script" << EOF
#!/bin/bash
echo "============================================="
echo "     $PROJECT_NAME v$PROJECT_VERSION"
echo "     USER: $user"
echo "     SCRIPT: $script_name"
echo "============================================="
echo "============BEGIN SCRIPT OUTPUT============="
bash "$user_script_path" > "$temp_log" 2>&1
exit_code=\$?
echo "=============END SCRIPT OUTPUT=============="
exit \$exit_code
EOF
        else
            # Wrapper without output redirection
            cat > "$wrapper_script" << EOF
#!/bin/bash
echo "============================================="
echo "     $PROJECT_NAME v$PROJECT_VERSION"
echo "     USER: $user"
echo "     SCRIPT: $script_name"
echo "============================================="
echo "============BEGIN SCRIPT OUTPUT============="
bash "$user_script_path"
exit_code=\$?
echo "=============END SCRIPT OUTPUT=============="
exit \$exit_code
EOF
        fi

        chown "$user:staff" "$wrapper_script"
        chmod 700 "$wrapper_script"

        log_message OK "Created wrapper script for $user"

        # Run wrapper script as user in background
        sudo -u "$user" bash "$wrapper_script" &
        local pid=$!
        pids+=("$pid")
        user_list+=("$user")
        user_script_paths+=("$user_script_path")
        temp_log_paths+=("$temp_log")

        log_message OK "Task started for: $user (PID: $pid)"
    done

    # SECURITY: Clear PAT from memory immediately after all downloads complete
    github_pat=""
    unset github_pat

    if [[ ${#pids[@]} -eq 0 ]]; then
        log_message ERROR "Failed to start tasks for any users"
        exit 1
    fi

    log_message INFO "Created tasks for ${#pids[@]} user(s)"
    
    log_message INFO "Monitoring task completion (max wait: $runAsUserTimeout seconds)..."
    
    # Wait for all processes with timeout
    local elapsed=0
    local all_completed=false
    
    while [[ $elapsed -lt $runAsUserTimeout ]] && [[ $all_completed == false ]]; do
        all_completed=true
        
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                all_completed=false
                break
            fi
        done
        
        if [[ $all_completed == false ]]; then
            sleep 5
            elapsed=$((elapsed + 5))
        fi
    done
    
    if [[ $all_completed == true ]]; then
        log_message OK "All user tasks completed"
    else
        log_message WARN "Some tasks may still be running after timeout"
    fi

    # Move temp logs to User directory and display output
    if [[ "$loggingMode" == "Full" ]]; then
        for i in "${!temp_log_paths[@]}"; do
            local temp_log="${temp_log_paths[$i]}"
            local user="${user_list[$i]}"

            if [[ -n "$temp_log" ]] && [[ -f "$temp_log" ]]; then
                # Build final log filename with username
                local final_log_name="${timestamp}_${script_name}_${user}.output.log"
                local final_log_path="$LOG_DIR_USER/$final_log_name"

                # Move temp log to User directory
                mv "$temp_log" "$final_log_path" 2>/dev/null || true

                if [[ -f "$final_log_path" ]]; then
                    log_message INFO "Moved output log for $user to: $final_log_name"

                    # Display the output
                    echo "============================================="
                    echo "     OUTPUT FROM: $user"
                    echo "============================================="
                    echo "============BEGIN SCRIPT OUTPUT============="
                    cat "$final_log_path"
                    echo "=============END SCRIPT OUTPUT=============="
                fi
            fi
        done

        # Clean up any orphaned temp logs
        cleanup_temp_logs
    fi

    # Check exit codes
    log_message INFO "Checking task exit codes..."
    
    local worst_exit_code=0
    local has_exit_one=false
    
    for i in "${!pids[@]}"; do
        local pid="${pids[$i]}"
        local user="${user_list[$i]}"
        
        # Wait for process and get exit code
        wait "$pid" 2>/dev/null
        local exit_code=$?
        
        # Track exit codes
        if [[ $exit_code -eq 1 ]]; then
            has_exit_one=true
            log_message ERROR "Task for $user: ERROR (exit code: 1)"
        elif [[ $exit_code -eq 0 ]]; then
            log_message OK "Task for $user: SUCCESS (exit code: 0)"
        else
            log_message ERROR "Task for $user: FAILURE (exit code: $exit_code)"
            if [[ $exit_code -gt $worst_exit_code ]]; then
                worst_exit_code=$exit_code
            fi
        fi
    done
    
    # Cleanup - remove each user's scripts and wrappers
    log_message INFO "Cleaning up user script directories..."
    for i in "${!user_script_paths[@]}"; do
        local path="${user_script_paths[$i]}"
        local user_dir=$(dirname "$path")
        if [[ -d "$user_dir" ]]; then
            # Remove all scripts and wrappers in user's directory
            rm -f "$user_dir"/*.sh "$user_dir"/*.sig 2>/dev/null
            log_message INFO "Cleaned up directory for ${user_list[$i]}"
        fi
    done
    
    # Determine final exit code
    if [[ $has_exit_one == true ]]; then
        log_message ERROR "At least one task exited with code 1, returning exit code: 1"
        return 1
    elif [[ $worst_exit_code -gt 0 ]]; then
        log_message WARN "Returning worst exit code: $worst_exit_code"
        return $worst_exit_code
    else
        log_message OK "All tasks succeeded, returning exit code: 0"
        return 0
    fi
}

################################################################################
# MAIN EXECUTION
################################################################################

gitexec_main() {
    check_root

    # Setup logging infrastructure
    if [[ "$loggingMode" != "None" ]]; then
        ensure_log_directories
        cleanup_old_logs
    fi

    # Create timestamp and script name
    local timestamp=$(date "+%Y-%m-%d_%H-%M-%S")
    local script_name
    script_name=$(basename "$scriptUrl")

    # Determine log directory based on execution mode
    local log_dir
    if [[ "$runAsUser" == "true" ]]; then
        log_dir="$LOG_DIR_USER"
    else
        log_dir="$LOG_DIR_SYSTEM"
    fi

    # Start transcript if logging enabled
    if [[ "$loggingMode" != "None" ]]; then
        local transcript_log="$log_dir/${timestamp}_${script_name}.log"
        # Use script command for transcript-like logging (tee alternative)
        exec &> >(tee -a "$transcript_log")
    fi

    log_message START "$PROJECT_NAME v$PROJECT_VERSION starting"
    if [[ "$loggingMode" != "None" ]]; then
        log_message INFO "Logging mode: $loggingMode"
        log_message INFO "Transcript log: $transcript_log"
    fi
    log_message INFO "Target script: $script_name"

    # Execute based on mode
    local exit_code
    if [[ "$runAsUser" == "true" ]]; then
        log_message INFO "Run as user mode: Executing $script_name for all logged-in users"
        execute_script_as_users "$timestamp" "$script_name"
        exit_code=$?
    else
        # Convert URL
        local remote_url
        if [[ "$useAPI" == "true" ]]; then
            log_message INFO "Using GitHub API (cache-bypass mode)"
            remote_url=$(convert_github_url_to_api "$scriptUrl")
        else
            log_message INFO "Converting GitHub URL to raw format"
            remote_url=$(convert_github_url_to_raw "$scriptUrl")
        fi
        log_message INFO "Converted URL: $remote_url"
        
        # Get PAT
        local github_pat
        github_pat=$(get_github_pat)

        # Download script AND signature
        local script_path
        script_path=$(download_payload_script "$remote_url" "$github_pat" "$runAsUser")

        # SECURITY: Clear PAT from memory immediately after use
        github_pat=""
        unset github_pat

        if [[ -z "$script_path" ]] || [[ ! -f "$script_path" ]]; then
            log_message ERROR "Failed to download script"
            exit 1
        fi
        
        # VERIFY SIGNATURE BEFORE EXECUTION
        log_message INFO "========================================"
        log_message INFO "SECURITY: Verifying script signature"
        log_message INFO "========================================"
        
        if ! verify_script_signature "$script_path"; then
            log_message ERROR "========================================"
            log_message ERROR "SECURITY ALERT: Signature verification failed"
            log_message ERROR "========================================"
            log_message ERROR "This could indicate:"
            log_message ERROR "  - Script has been tampered with"
            log_message ERROR "  - Signature file is invalid or corrupt"
            log_message ERROR "  - Public key mismatch"
            log_message ERROR "  - Man-in-the-middle attack"
            log_message ERROR ""
            log_message ERROR "REFUSING TO EXECUTE for security reasons"
            
            # Clean up
            rm -f "$script_path"
            rm -f "${script_path}.sig"
            
            exit 1
        fi
        
        log_message OK "========================================"
        log_message OK "SECURITY: Script verified - safe to execute"
        log_message OK "========================================"
        
        # Execute script as root
        log_message INFO "Run as root mode: Executing $script_name"
        execute_script_as_root "$script_path" "$timestamp" "$script_name"
        exit_code=$?
        
        if [[ $exit_code -eq 0 ]]; then
            log_message OK "$script_name completed successfully (exit code: 0)"
        else
            log_message WARN "$script_name completed with exit code: $exit_code"
        fi
        
        # Cleanup
        if [[ -f "$script_path" ]]; then
            rm -f "$script_path"
            rm -f "${script_path}.sig"
            log_message INFO "Cleaned up downloaded script and signature"
        fi
    fi

    log_message COMPLETE "$PROJECT_NAME execution finished"
    exit $exit_code
}