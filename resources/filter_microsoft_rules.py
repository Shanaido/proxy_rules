import requests
import ruamel.yaml
import tldextract

microsoft_rules_url = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.yaml"
github_rules_url = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/github.yaml"

yaml = ruamel.yaml.YAML()
yaml.indent(mapping=4, sequence=4, offset=4)

def get_payload(url):
    text = requests.get(url).text
    data = yaml.load(text)
    return set(data.get("payload", []))

def parse_rule(rule):
    return tldextract.extract(rule.lstrip("+*."))

def rule_covers(rule_parsed, domain_parsed, rule, domain):
    if domain_parsed.domain != rule_parsed.domain or domain_parsed.suffix != rule_parsed.suffix:
        return False
    if rule.startswith("+."):
        return True
    if rule.startswith("."):
        return bool(domain_parsed.subdomain)
    if rule.startswith("*."):
        return domain_parsed.subdomain.count('.') == 0
    return rule == domain

def keep_most_general(rules):
    parsed_rules = {r: parse_rule(r) for r in rules}
    temp_sorted = sorted(rules, key=len)
    kept = []
    for rule in temp_sorted:
        rp = parsed_rules[rule]
        if any(rule_covers(parsed_rules[existing], rp, existing, rule) for existing in kept):
            continue
        kept.append(rule)
    return sorted(kept)

microsoft_rules = get_payload(microsoft_rules_url)
github_rules = get_payload(github_rules_url)

filtered_rules = microsoft_rules - github_rules

filtered_rules = keep_most_general(filtered_rules)

with open("microsoft.yaml", "w", encoding="utf-8") as f:
    yaml.dump({"payload": filtered_rules}, f)
