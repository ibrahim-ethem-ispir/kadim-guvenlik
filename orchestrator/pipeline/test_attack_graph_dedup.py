"""Bulgu dedup + host kanonikleştirme testleri.

Gerçek vaka regresyonu: blog.X ile www.blog.X ayrı host sayılıp aynı pathprobe
bulgusu iki kez, aynı nuclei template'i birden çok kenardan beş kez kanıtlanıyordu.
Kurumsal raporda mükerrer bulgu güven kırar — dedup grafın tek otoritesidir.
"""

from pipeline.attack_graph import Graph, _canon_host, _canon_url


def test_canon_host_strips_www_and_scheme():
    assert _canon_host("https://www.blog.example.com/a") == "blog.example.com"
    assert _canon_host("WWW.Example.COM") == "example.com"
    assert _canon_host("blog.example.com") == "blog.example.com"
    assert _canon_host("1.2.3.4") == "1.2.3.4"
    assert _canon_host("example.com:8443") == "example.com"


def test_canon_url_keeps_query_drops_trailing_slash():
    assert _canon_url("https://www.x.com/wp-admin/?action=postpass") == "x.com/wp-admin/?action=postpass"
    assert _canon_url("https://x.com/a/") == "x.com/a"
    # Aynı adresin www'lu/www.'suz biçimleri tek parmak izine düşer
    assert _canon_url("https://www.x.com/a") == _canon_url("http://x.com/a/")


def _nuclei_result(matched_at: str):
    return {"findings": [{
        "template-id": "cve-2024-2473",
        "matched-at": matched_at,
        "info": {"name": "WPS Hide Login <= 1.9.15.2 - Login Page Disclosure",
                 "severity": "medium",
                 "classification": {"cve-id": ["CVE-2024-2473"]}},
    }]}


def test_nuclei_evidence_dedup_same_template_same_url():
    g = Graph(target="blog.example.com", target_is_ip=False)
    g.integrate(None, _nuclei_result("https://blog.example.com/wp-admin/?action=postpass"), "nuclei")
    # Aynı template aynı adres ikinci bir kenardan tekrar tetiklendi
    g.integrate(None, _nuclei_result("https://blog.example.com/wp-admin/?action=postpass"), "nuclei")
    assert len(g.graph_evidence() if hasattr(g, "graph_evidence") else g.evidence) == 1


def test_nuclei_evidence_dedup_across_www_variant():
    g = Graph(target="blog.example.com", target_is_ip=False)
    g.integrate(None, _nuclei_result("https://blog.example.com/wp-admin/?action=postpass"), "nuclei")
    g.integrate(None, _nuclei_result("https://www.blog.example.com/wp-admin/?action=postpass"), "nuclei")
    assert len(g.evidence) == 1


def test_pathprobe_evidence_dedup_across_www_variant():
    g = Graph(target="blog.example.com", target_is_ip=False)
    finding = {
        "severity": "medium", "category": "info_disclosure", "validator": "directory_listing",
        "path": "/wp-content/uploads/", "status": 200, "content_length": 1191,
    }
    g.integrate(None, {"findings": [{**finding, "url": "https://blog.example.com/wp-content/uploads/"}]}, "pathprobe")
    g.integrate(None, {"findings": [{**finding, "url": "https://www.blog.example.com/wp-content/uploads/"}]}, "pathprobe")
    assert len(g.evidence) == 1


def test_target_itself_not_duplicated_as_subdomain():
    g = Graph(target="blog.example.com", target_is_ip=False)
    g.integrate(None, {"subdomains": ["blog.example.com", "www.blog.example.com", "api.example.com"]}, "subfinder")
    host_labels = {n.label for n in g.nodes.values() if n.type.value == "host"}
    assert "blog.example.com" not in host_labels
    assert "www.blog.example.com" not in host_labels
    assert "api.example.com" in host_labels


def test_distinct_findings_survive_dedup():
    g = Graph(target="blog.example.com", target_is_ip=False)
    g.integrate(None, _nuclei_result("https://blog.example.com/a"), "nuclei")
    g.integrate(None, _nuclei_result("https://blog.example.com/b"), "nuclei")
    assert len(g.evidence) == 2


# --- RAID / bütçe-israfı regresyonları (Adım 6-10 + 12-20 çift RAID vakası) ---

def _raid_edges(g, host_id):
    return [e for e in g.edges.values()
            if e.tool == "pathprobe" and e.from_id == host_id and "path_base" not in e.options]


def test_raid_dedup_signature_level_not_host_level():
    """REGRESYON KORUMASI: Aynı tech_hints ile ikinci RAID dedup'lanır; ama FARKLI
    tech_hints ile gelen RAID YASALDIR — _paths_for_tech kataloğa framework-özel yollar
    ekler (/wp-content/uploads/, /wp-json/wp/v2/users). Kök raid recon'dan önce hints'siz
    çalışır; recon'un teknoloji tespiti sonrası hints'li ikinci raid asıl bulguları üretir.
    Host-seviyesi dedup bu ikinci geçişi engelleyip gerçek bulguları kaybettirmişti."""
    g = Graph(target="blog.example.com", target_is_ip=False)
    assert g._seed_pathprobe_raid(g.root_id, None, "kök") is True
    # Aynı (boş) hints → aynı katalog → dedup
    assert g._seed_pathprobe_raid(g.root_id, None, "kök") is False
    # Farklı hints → farklı yol kataloğu → YENİ RAID GEREKLİ (bulgular buradan gelir)
    assert g._seed_pathprobe_raid(g.root_id, None, "kök", tech_hints=["wordpress"]) is True
    # Aynı hints tekrar → dedup
    assert g._seed_pathprobe_raid(g.root_id, None, "kök", tech_hints=["wordpress"]) is False
    assert len(_raid_edges(g, g.root_id)) == 2


def test_boilerplate_subdomain_no_deep_scan_seeds():
    """cPanel varsayılan kayıtları (webdisk/webmail/whm...) node olarak kalır ama
    recon/RAID kenarı seed edilmez — adım bütçesi asıl yüzeye saklanır."""
    g = Graph(target="blog.example.com", target_is_ip=False)
    g.integrate(None, {"subdomains": ["webdisk.blog.example.com", "webmail.blog.example.com",
                                      "api.blog.example.com"]}, "subfinder")
    boiler = g.nodes.get("host:webdisk.blog.example.com")
    assert boiler is not None and boiler.meta.get("boilerplate") is True
    # boilerplate host'a pathprobe raid seed edilmedi, gerçek subdomain'e edildi
    assert len(_raid_edges(g, "host:webdisk.blog.example.com")) == 0
    assert len(_raid_edges(g, "host:webmail.blog.example.com")) == 0
    assert len(_raid_edges(g, "host:api.blog.example.com")) == 1


def test_llm_suggested_edge_cap_per_tool():
    """LLM aynı aracı farklı gerekçe/tag ile kaç kez önerirse önersin en fazla 2 kenar
    açılır (gerçek vaka: 7 turda 5x 'nuclei ile CVE tara', hepsi farklı signature)."""
    g = Graph(target="blog.example.com", target_is_ip=False)
    for tags in (["cve"], ["wordpress"], ["apache"], ["xss"], ["sqli"]):
        g.apply_intel({"suggested_edges": [{"tool": "nuclei", "why": "CVE tara", "tags": tags}]})
    llm_nuclei = [e for e in g.edges.values() if e.tool == "nuclei" and e.meta.get("from_llm")]
    assert len(llm_nuclei) == 2


# --- Sürüm parmak izi → NVD zinciri (güncel WordPress CVE'si vakası) ---

def test_pathprobe_detected_tech_creates_cve_lookup_node():
    g = Graph(target="blog.example.com", target_is_ip=False)
    g.integrate(None, {
        "target": "blog.example.com",
        "findings": [],
        "detected_technologies": [
            {"product": "wordpress", "version": "6.7.1", "source": "meta-generator"},
            {"product": "apache", "version": "2.4.62", "source": "server-header"},
        ],
    }, "pathprobe")
    wp = g.nodes.get("svc:web:wordpress@blog.example.com")
    assert wp is not None, "sürümlü ürün SERVICE düğümü olmalı"
    assert wp.meta.get("needs_cve_lookup") is True, "sürüm var → NVD lookup tetiklenmeli"
    assert wp.meta.get("version") == "6.7.1"
    # WordPress için ürüne-özel nuclei tag kenarı da seed edilmeli
    assert any(e.tool == "nuclei" and e.options.get("tags") == ["wordpress"]
               for e in g.edges.values())
    # Teknoloji root meta'sına da işlenmeli (LLM/özet görünürlüğü)
    assert "wordpress" in [t.lower() for t in g.nodes[g.root_id].meta.get("technologies", [])]


def test_pathprobe_detected_tech_without_version_skips_nvd():
    g = Graph(target="blog.example.com", target_is_ip=False)
    g.integrate(None, {
        "target": "blog.example.com",
        "findings": [],
        "detected_technologies": [{"product": "wordpress", "version": "", "source": "wp-asset"}],
    }, "pathprobe")
    wp = g.nodes.get("svc:web:wordpress@blog.example.com")
    assert wp is not None
    assert wp.meta.get("needs_cve_lookup") is not True, "sürüm yok → NVD sorgusu anlamsız"


# --- UÇTAN UCA ZİNCİR: sürüm parmak izi → NVD → hedefli nuclei (güncel CVE yakalama) ---

class _FakeCVEIntel:
    """cve_intel'in sahtesi: NVD'ye gitmeden zincirin davranışını doğrular."""
    CVE_INTEL_ENABLED = True

    class Hit:
        def __init__(self, cve_id, score):
            self.cve_id = cve_id
            self.cvss_score = score
            self.severity = "critical" if score >= 9 else "high"
            self.description = "fake"

    async def lookup(self, product, version):
        if product == "wordpress":
            return [self.Hit("CVE-2024-10001", 9.8)]
        if product == "contact-form-7":
            return [self.Hit("CVE-2024-20002", 7.5)]
        return []

    @staticmethod
    def cve_ids_to_nuclei_templates(cve_ids):
        return [c.lower() for c in cve_ids]


class _FakeKEVIntelDisabled:
    """kev_intel'in kapalı sahtesi: bu test NVD zincirini doğrular; KEV/EPSS
    (test_kev_intel.py'nin konusu) ağa çıkmasın, sonuç deterministik kalsın."""
    KEV_INTEL_ENABLED = False


async def test_version_to_nvd_to_targeted_nuclei_chain(monkeypatch):
    """wordpress 6.7.1 + eklenti sürümü tespit edilince: her turda çalışan
    enrich_cve_intelligence NVD'ye sorar, CVE düğümü + HEDEFLİ nuclei template kenarı doğar.
    'Güncel açık sende var mı?' sorusunun çalışan kanıtı budur."""
    import pipeline.attack_graph as ag
    monkeypatch.setattr(ag, "_cve_intel", _FakeCVEIntel())
    monkeypatch.setattr(ag, "_kev_intel", _FakeKEVIntelDisabled())

    g = ag.Graph(target="blog.example.com", target_is_ip=False)
    g.integrate(None, {
        "target": "blog.example.com",
        "findings": [],
        "detected_technologies": [
            {"product": "wordpress", "version": "6.7.1", "source": "meta-generator"},
            {"product": "contact-form-7", "version": "5.9.2", "source": "wp-plugin-readme"},
            {"product": "apache", "version": "2.4.62", "source": "server-header"},
        ],
    }, "pathprobe")

    result = await g.enrich_cve_intelligence()
    assert result["lookups"] >= 2
    assert result["new_cves"] == 2

    # CVE düğümleri doğdu
    assert "vuln:CVE-2024-10001" in g.nodes
    assert "vuln:CVE-2024-20002" in g.nodes

    # Hedefli nuclei template kenarları doğdu (kör tarama değil — bu CVE'yi KANITLA)
    tpl_edges = [e for e in g.edges.values()
                 if e.tool == "nuclei" and e.options.get("templates")]
    tpls = {t for e in tpl_edges for t in e.options["templates"]}
    assert "cve-2024-10001" in tpls
    assert "cve-2024-20002" in tpls

    # needs_cve_lookup işareti tüketildi — aynı turda tekrar sorgulanmaz
    wp = g.nodes["svc:web:wordpress@blog.example.com"]
    assert wp.meta.get("needs_cve_lookup") is False
