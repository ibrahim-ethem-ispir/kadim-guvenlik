"""
Kadim Güvenlik — attention_items servis sınıflandırma testleri.

REGRESYON KORUMASI: attention_items() servis türünü düğümün DEĞER SKORUNDAN değil
GERÇEK KİMLİĞİNDEN türetmeli. Eskiden value>=eşik ile tahmin ediliyordu; web-app değeri
(boost'la) database eşiğini geçince nginx "Veritabanı servisi, kritik" olarak raporlanıyordu
— banka müşterisine gösterilen kredibilite katili hata. Bu testler kimliğe-göre sınıflamayı
ve değer-skoru-körlüğünü pinler. Repo konvansiyonu: düz script (pytest yok).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pipeline.attack_graph import Graph, Node, NodeType, NodeState, _service_attention  # noqa: E402


def _svc(label, value, meta):
    return Node(id=f"svc:{label}", type=NodeType.SERVICE, label=label,
                value=value, breach_prob=0.3, state=NodeState.DISCOVERED, meta=meta)


def _find(items, label):
    for it in items:
        if it["label"] == label:
            return it
    raise AssertionError(f"{label} attention_items içinde yok: {[i['label'] for i in items]}")


def test_nginx_is_web_not_database_despite_inflated_value():
    """KÖK BUG: value şişse (95 ≥ database=90) bile nginx web olarak sınıflanmalı."""
    g = Graph(target="portal.test", target_is_ip=False)
    # value=95 → eski kod "database, critical" derdi. Kimlik "nginx" → web olmalı.
    g.add_node(_svc("nginx@portal.test", 95.0,
                    {"product": "nginx", "matched_service": "nginx"}))
    items = g.attention_items()
    it = _find(items, "nginx@portal.test")
    assert it["severity"] == "medium", it
    assert "Veritabanı" not in it["reason"], f"nginx hâlâ veritabanı görünüyor: {it}"
    assert "Web" in it["reason"], it
    print("[OK] test_nginx_is_web_not_database_despite_inflated_value")


def test_ssh_by_product_openssh_maps_remote_mgmt():
    """nmap düğümünde servis adı 'ssh', ürün 'openssh' — alt-dize eşleşmesiyle remote-mgmt."""
    g = Graph(target="1.2.3.4", target_is_ip=True)
    g.add_node(_svc("ssh@22", 75.0,
                    {"port": 22, "product": "openssh 8.9p1", "version": "8.9p1",
                     "matched_service": "ssh"}))
    it = _find(g.attention_items(), "ssh@22")
    assert it["severity"] == "high", it
    assert "Uzaktan yönetim" in it["reason"], it
    assert "sürüm tespit edildi" in it["reason"], it  # versiyon ipucu korunur
    print("[OK] test_ssh_by_product_openssh_maps_remote_mgmt")


def test_mysql_is_database_critical():
    """Gerçek veritabanı GERÇEKTEN database/critical olmalı (yanlış negatif olmasın)."""
    g = Graph(target="1.2.3.4", target_is_ip=True)
    g.add_node(_svc("mysql@3306", 90.0, {"port": 3306, "matched_service": "mysql"}))
    it = _find(g.attention_items(), "mysql@3306")
    assert it["severity"] == "critical" and "Veritabanı" in it["reason"], it
    print("[OK] test_mysql_is_database_critical")


def test_unknown_high_value_service_stays_low():
    """Kimliği tanınmayan yüksek-değerli servis 'database' TAHMİN EDİLMEMELİ — nötr low."""
    g = Graph(target="1.2.3.4", target_is_ip=True)
    # value=95 ama ne servis adı ne bilinen port var → unknown/low.
    g.add_node(_svc("mystery@9999", 95.0, {"port": 9999}))
    it = _find(g.attention_items(), "mystery@9999")
    assert it["severity"] == "low", it
    assert "Veritabanı" not in it["reason"], it
    print("[OK] test_unknown_high_value_service_stays_low")


def test_port_fallback_when_no_service_name():
    """Servis adı yoksa bilinen porttan kategori: 5432→database, 3389→remote-mgmt, 443→web."""
    class N:
        def __init__(s, meta, label=""):
            s.meta = meta; s.label = label
    assert _service_attention(N({"port": 5432}))[0] == "database"
    assert _service_attention(N({"port": 3389}))[0] == "remote-mgmt"
    assert _service_attention(N({"port": 443}))[0] == "web-app"
    assert _service_attention(N({"port": 12345}))[0] == "unknown"
    print("[OK] test_port_fallback_when_no_service_name")


def test_label_prefix_classification():
    """Meta boş olsa bile label öneki (ör. 'redis@6379') kimlik verir."""
    class N:
        def __init__(s, meta, label): s.meta = meta; s.label = label
    cat, sev, _ = _service_attention(N({}, "redis@6379"))
    assert cat == "database" and sev == "critical"
    print("[OK] test_label_prefix_classification")


if __name__ == "__main__":
    test_nginx_is_web_not_database_despite_inflated_value()
    test_ssh_by_product_openssh_maps_remote_mgmt()
    test_mysql_is_database_critical()
    test_unknown_high_value_service_stays_low()
    test_port_fallback_when_no_service_name()
    test_label_prefix_classification()
    print("\nTüm testler geçti.")
