import YAML from "yaml";

export async function loadRulePack(url = "/rulepacks/kr-medhealth.yaml") {
  const text = await fetch(url, { cache: "no-store" }).then((r) => r.text());
  const pack = YAML.parse(text);
  // 패턴 미리 컴파일
  for (const r of pack.rules) {
    const list = r.patterns?.any || r.patterns || [];
    r._regexes = list.filter((p) => p.type === "regex").map((p) => new RegExp(p.value, "giu"));
    r._keywords = list.filter((p) => p.type !== "regex").map((p) => String(p.value).toLowerCase());
    r._excepts = (r.exceptions || []).map((ex) => new RegExp(ex, "giu"));
  }
  return pack;
}