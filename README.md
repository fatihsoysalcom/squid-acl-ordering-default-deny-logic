# Squid ACL Ordering Default Deny Logic

This example simulates the core logic of Squid proxy's Access Control Lists (ACLs), demonstrating how rules are processed in order and how the first matching rule dictates the action. It highlights the critical importance of correct ACL ordering (specific denies before general allows) and the necessity of an explicit 'default deny' policy to prevent security vulnerabilities. The script shows both a correctly configured and a misconfigured set of ACLs.

## Language

`python`

## How to Run

Save the code as `main.py`. Run from your terminal: `python main.py`

## Original Article

This example accompanies the Turkish article: [Squid Proxy Güvenliğinde ACL Sıralaması ve Varsayılan Kapalı Politikanın Önemi](https://fatihsoysal.com/blog/squid-proxy-guvenliginde-acl-siralamasi-ve-varsayilan-kapali-politikanin-onemi/).

## License

MIT — see [LICENSE](LICENSE).
