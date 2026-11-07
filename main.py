import ipaddress

def check_access(client_ip_str, requested_url, acl_rules):
    """
    Simulates Squid ACL processing for a given client IP and requested URL.
    Rules are processed in order; the first match determines the action.
    """
    print(f"\n--- Checking access for IP: {client_ip_str}, URL: {requested_url} ---")
    try:
        client_ip = ipaddress.ip_address(client_ip_str)
    except ValueError:
        print(f"  Invalid IP address format: {client_ip_str}")
        return "deny"

    for i, rule in enumerate(acl_rules):
        print(f"  [Rule {i+1}] Evaluating: {rule['description']}")
        match = False

        # ACL Type: Source IP (specific IP or network range)
        if rule["type"] == "src_ip":
            try:
                # Check if client_ip is within the specified network or matches a specific IP
                if client_ip in ipaddress.ip_network(rule["match"], strict=False):
                    match = True
            except ValueError:
                # This handles cases where rule['match'] might be a malformed IP/network
                pass # No match if rule['match'] is invalid
        
        # ACL Type: Destination Domain
        elif rule["type"] == "dst_domain":
            # Simple substring check for domain. In real Squid, it's more robust.
            if rule["match"] in requested_url:
                match = True
        
        # ACL Type: Always match (used for explicit default policy)
        elif rule["type"] == "any":
            match = True

        if match:
            # This is where ACL ordering is critical: the first match wins.
            print(f"  [Rule {i+1}] MATCH! Action: {rule['action'].upper()} - {rule['description']}")
            return rule["action"]

    # If no rule matched, and no explicit 'deny any' rule was present as the last rule,
    # this indicates a misconfiguration or an implicit deny. The article emphasizes
    # having an explicit default deny.
    print("  ERROR: No ACL rule matched and no explicit 'deny any' rule was found. Applying implicit DENY.")
    return "deny" 

# --- Define ACL Rules --- 
# Rules are processed in the order they appear. This demonstrates a GOOD ACL configuration
# with proper ordering (specific DENY before general ALLOW) and an explicit default deny.
good_acl_rules = [
    # ACL 1: Deny access from a specific problematic internal IP.
    # This rule comes first to ensure this IP is blocked regardless of other rules.
    {"type": "src_ip", "match": "192.168.1.10", "action": "deny", "description": "DENY problematic internal IP (192.168.1.10)"},
    
    # ACL 2: Deny access to known bad domains.
    # Specific denies should generally come before general allows to be effective.
    {"type": "dst_domain", "match": "badsite.com", "action": "deny", "description": "DENY known bad site (badsite.com)"},
    {"type": "dst_domain", "match": "malware.net", "action": "deny", "description": "DENY another malicious domain (malware.net)"},

    # ACL 3: Allow internal network to most sites.
    # This is a general allow for trusted clients, placed after specific denies.
    {"type": "src_ip", "match": "192.168.1.0/24", "action": "allow", "description": "ALLOW internal network (192.168.1.x) to most sites"},
    
    # ACL 4: Explicit Default Deny.
    # This is crucial. If no previous rule matched, access is explicitly denied.
    # This prevents unintended access and is the cornerstone of a secure proxy policy.
    {"type": "any", "action": "deny", "description": "DEFAULT DENY for all other traffic (explicit policy)"}
]

# This demonstrates a BAD ACL configuration where ordering creates a vulnerability.
# The general ALLOW rule is placed before the specific DENY for badsite.com,
# effectively allowing internal IPs to access badsite.com.
bad_acl_rules = [
    # ACL 1: Allow internal network to most sites (TOO GENERAL, TOO EARLY).
    # This rule will match for 192.168.1.x IPs accessing badsite.com before the deny rule.
    {"type": "src_ip", "match": "192.168.1.0/24", "action": "allow", "description": "ALLOW internal network (192.168.1.x) to most sites (VULNERABLE ORDER)"},
    
    # ACL 2: Deny access to known bad domains.
    # This rule is now ineffective for clients matching the preceding ALLOW rule.
    {"type": "dst_domain", "match": "badsite.com", "action": "deny", "description": "DENY known bad site (badsite.com) - *Ineffective due to order*"},
    {"type": "dst_domain", "match": "malware.net", "action": "deny", "description": "DENY another malicious domain (malware.net)"},
    
    # ACL 3: Explicit Default Deny (still important, but doesn't fix the ordering issue).
    {"type": "any", "action": "deny", "description": "DEFAULT DENY for all other traffic"}
]

# --- Test Scenarios --- 

print("\n=================================================================")
print("--- Scenario 1: Demonstrating GOOD ACL Ordering and Default Deny ---")
print("   (Specific DENY rules before general ALLOW, followed by DEFAULT DENY)")
print("=================================================================")

# Test 1: Problematic IP accessing a good site (should be DENIED by Rule 1)
check_access("192.168.1.10", "http://www.goodsite.com", good_acl_rules)

# Test 2: Internal IP accessing a bad site (should be DENIED by Rule 2)
check_access("192.168.1.20", "http://www.badsite.com", good_acl_rules)

# Test 3: Internal IP accessing a good site (should be ALLOWED by Rule 3)
check_access("192.168.1.30", "http://www.anothersite.org", good_acl_rules)

# Test 4: External IP accessing any site (should be DENIED by Rule 4 - Default Deny)
check_access("10.0.0.5", "http://www.externalsite.com", good_acl_rules)

print("\n\n=================================================================")
print("--- Scenario 2: Demonstrating BAD ACL Ordering (Vulnerability) ---")
print("   (General ALLOW rule placed before specific DENY rule)")
print("=================================================================")

# Test 5: Internal IP accessing a bad site (should be ALLOWED by Rule 1 in bad_acl_rules,
#          bypassing the intended deny for badsite.com, demonstrating a vulnerability)
check_access("192.168.1.20", "http://www.badsite.com", bad_acl_rules)

# Test 6: External IP accessing any site (still DENIED by Default Deny, as expected)
check_access("10.0.0.5", "http://www.anothersite.org", bad_acl_rules)
