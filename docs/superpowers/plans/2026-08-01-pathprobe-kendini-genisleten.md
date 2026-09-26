# PathProbe Kendini-Genişleten Prober — Implementasyon Planı

> **Agentic worker için:** Kaynak spec: [../specs/2026-08-01-pathprobe-kendini-genisleten-tasarim.md](../specs/2026-08-01-pathprobe-kendini-genisleten-tasarim.md)

**Goal:** PathProbe'u hedefe-kör statik listeden; hedefe göre kendini genişleten (şablon+kanıt),
LLM ile danışan ve geçmişten öğrenen hibrit prober'a çevir — determinizmi/felsefeyi bozmadan.

**Architecture:** `path_probe.py` SAF kalır; zekâ (LLM/Mongo) dispatcher sınırında üretilip `paths=`
ile enjekte edilir. K0 küratörlü çekirdek + K1 şablon/kanıt (saf, det.) + K2 LLM öneri (opsiyonel) +
K3 öğrenme döngüsü (Mongo). Yargı her zaman içeride ve deterministik.

**Tech Stack:** Python 3, httpx (mevcut), Mongo (mevcut singleton), mevcut LLM katmanı
(`resolve_ai_service_default`). Test: düz-script + `httpx.MockTransport` (pytest YOK — repo konvansiyonu).

## Global Constraints (spec'ten aynen)

- Yorum dili **Türkçe**, "neden"i açıklar. `path_probe.py` **saf** kalır (Mongo/LLM istemcisi YOK).
- Motor felsefesi: **LLM opsiyonel, kritik yol değil.** K2/K3 env-flag arkasında; kapalıyken davranış
  bugünküyle **bit-bit aynı** (regresyon yok).
- Testler düz Python scripti (`def test_*` + `main()`); çalıştırma: `python3 pipeline/test_xxx.py`.
- Yalnız GET, düşük eşzamanlılık, kısa timeout; sırlar maskeli; path sanitize (aynı host).
- Kaynak tavanları: aile ≤40, kanıt ≤40, LLM ≤30, hafıza ≤50. `partial` hangi kaynağın kesildiğini der.
- **Commit YOK** (kullanıcı istemedikçe); k3'ün commit'siz işi olduğu gibi kalır, üstüne eklenir.

## Dosya Yapısı

| Dosya | Sorumluluk | İşlem |
|---|---|---|
| `orchestrator/pipeline/path_probe.py` | K0+K1: çekirdek + şablon + kanıt + signature-validator + önce-değer sıralama + `source` | Modify |
| `orchestrator/pipeline/path_intel.py` | K2: `suggest_paths_llm(fingerprint)` + sanitize/clamp | Create |
| `orchestrator/pipeline/path_memory.py` | K3: `load_learned_paths` / `record_findings` / `learn_path_manual` | Create |
| `orchestrator/pipeline/scan_pipeline_v2.py` | `_dispatch_pathprobe`: K2+K3 enjeksiyonu (flag) | Modify (1999-2083) |
| `orchestrator/integrations/redteam_proxy.py` | `POST /redteam/learn-path` + canlı modda K2/K3 | Modify |
| `pipeline/test_path_probe_families.py` | K1 şablon testleri | Create |
| `pipeline/test_path_probe_evidence.py` | K1 kanıt-türetme + signature-validator + sıralama | Create |
| `pipeline/test_path_intel.py` | K2 sanitize/clamp/fallback | Create |
| `pipeline/test_path_memory.py` | K3 oku/yaz/birleştir (fake db) | Create |

### Anahtar iç arayüz — satır normalizasyonu (tüm fazların temeli)

`paths`/`catalog` satırları hem 4-tuple (mevcut) hem 5-tuple olabilir:
```
4-tuple: (path, category, severity, validator_name)                       # K0/K1 named-validator
5-tuple: (path, category, severity, validator_name, meta)                 # K2/K3 signature+source
   meta: {"signature": {...} | None, "source": "curated|template|evidence|llm|memory"}
```
`_normalize_row(row) -> (path, category, severity, validator_name, meta)` her ikisini de kabul eder;
`meta` yoksa `{"signature": None, "source": <varsayılan>}`. `validator_name == "signature"` ise
`_validate_from_signature(meta["signature"])` kullanılır. Bulgu `source` alanını `meta`'dan alır.

---

## FAZ K1 — Şablon + kanıt-türetme (deterministik, LLM/DB YOK)

Bu faz tek başına databases.yml sınıfını LLM'siz yakalar ve elle-kombinasyon kırılganlığını bitirir.

### Task 1: Satır normalizasyonu + `source` alanı + signature-validator

**Files:** Modify `orchestrator/pipeline/path_probe.py`; Test `pipeline/test_path_probe_evidence.py`

**Produces:**
- `_normalize_row(row) -> (path,cat,sev,vname,meta)`
- `_validate_from_signature(sig: dict) -> Callable[[int,str,str],bool]`
- Bulgu dict'ine `"source"` alanı.

**Test (gerçek kod):**
```python
from pipeline.path_probe import _normalize_row, _validate_from_signature

def test_normalize_4_ve_5_tuple():
    p,c,s,v,m = _normalize_row(("/x","cat","high","generic"))
    assert (p,v,m["source"],m["signature"]) == ("/x","generic","curated",None)
    p,c,s,v,m = _normalize_row(("/y","cat","low","signature",{"signature":{"must_contain_any":["a"]},"source":"llm"}))
    assert v=="signature" and m["source"]=="llm" and m["signature"]["must_contain_any"]==["a"]

def test_signature_validator_kurallari():
    val = _validate_from_signature({"must_contain_any":["DB_","define("],
                                    "must_not_contain":["<html"], "min_length":10})
    assert val(200,"", "DB_HOST=localhost app secret here") is True
    assert val(200,"", "<html>DB_HOST=x</html>") is False      # must_not_contain
    assert val(200,"", "short") is False                        # min_length + yok
    assert val(200,"", "nothing relevant but long enough text") is False  # must_contain_any yok
```
Çalıştır: `python3 pipeline/test_path_probe_evidence.py` → önce FAIL (fonksiyon yok), sonra PASS.

**Implementasyon notu:** `_validate_from_signature` html-reddi YALNIZ `must_not_contain`'de belirtilirse
uygular (admin panel gibi html bulgular için esnek). `signature` None ise generic'e düşer.

### Task 2: Yol-ailesi şablonları

**Files:** Modify `path_probe.py`; Test `pipeline/test_path_probe_families.py`

**Produces:** `PATH_FAMILIES: Dict`, `_expand_path_families(techs, discovered_apps=None) -> List[5-tuple]`
(source="template", ≤40/aile, `{app}` genişler).

**Test:**
```python
from pipeline.path_probe import _expand_path_families
def test_symfony_ailesi_apps_kombinasyonu_uretir():
    rows = _expand_path_families(["symfony 1.4"])
    paths = {r[0] for r in rows}
    assert "/symfony/config/databases.yml" in paths
    assert "/apps/api/config/databases.yml" in paths      # kimse elle yazmadı
    assert all(r[4]["source"]=="template" for r in rows)
    assert len(rows) <= 40
def test_bilinmeyen_tech_bos():
    assert _expand_path_families(["cobol"]) == []
def test_kesfedilen_app_eklenir():
    rows = _expand_path_families(["symfony"], discovered_apps=["mobil2"])
    assert any("/apps/mobil2/config/databases.yml"==r[0] for r in rows)
```

### Task 3: Kanıt-güdümlü türetme (saf parse fonksiyonları)

**Files:** Modify `path_probe.py`; Test `pipeline/test_path_probe_evidence.py`

**Produces (hepsi saf, I/O yok):**
- `_paths_from_robots(text) -> List[str]` (Disallow satırları)
- `_paths_from_git_config(text) -> List[str]` (remote url → repo → zip/tar.gz varyant)
- `_paths_from_dir_listing(html, base_path) -> List[str]` (`Index of` + href)
- `_backup_siblings(path) -> List[str]` (.bak/~/.old/.save/.orig/.dist/.swp)

**Test:**
```python
from pipeline.path_probe import _paths_from_robots, _paths_from_git_config, _backup_siblings, _paths_from_dir_listing
def test_robots_disallow_yol_uretir():
    assert "/admin/" in _paths_from_robots("User-agent: *\nDisallow: /admin/\nDisallow: /secret")
def test_git_config_repo_yedegi():
    cfg='[remote "origin"]\n url = git@github.com:acme/portal.git'
    out=_paths_from_git_config(cfg)
    assert "/portal.zip" in out and "/portal.tar.gz" in out
def test_yedek_kardesleri():
    out=_backup_siblings("/config.php")
    assert "/config.php.bak" in out and "/config.php~" in out
def test_dizin_listeleme_href():
    html='<title>Index of /backup</title><a href="db.sql">db.sql</a>'
    assert "/backup/db.sql" in _paths_from_dir_listing(html, "/backup")
```

### Task 4: İki-dalga + önce-değer sıralama + kaynak enjeksiyonu (`probe_sensitive_paths` entegrasyonu)

**Files:** Modify `path_probe.py` (`probe_sensitive_paths` gövdesi ~673-866); Test `test_path_probe_evidence.py`

**Consumes:** Task 1-3.
**Produces:** `probe_sensitive_paths(..., extra_paths: Optional[List]=None, discovered_apps=None)`;
katalog normalize edilir; fingerprint tech → `_expand_path_families`; görevler **(severity, source-öncelik)**
sırasıyla oluşturulur; ilk dalga sırasında robots/`.git/config`/dir-listing toplanır → ikinci dalga
(`_paths_from_*` + `_backup_siblings`) ≤40 kırpılıp problanır; bulgular `source` taşır.

**Test (MockTransport ile):**
```python
import asyncio, httpx
from pipeline import path_probe
def _mk(routes):  # path -> (status, body)
    def handler(req):
        st,body = routes.get(req.url.path, (404,"nope"))
        return httpx.Response(st, text=body)
    return httpx.MockTransport(handler)
def test_dus_deger_iptal_edilse_kritik_once(monkeypatch=None):
    # 200 databases.yml + gürültü; kritik yol her koşulda bulunur
    routes={"/symfony/config/databases.yml":(200,"all:\n propel:\n  param:\n   hostspec: db.x\n   username: u\n   password: p")}
    # base_url resolve + fetch MockTransport'a bağlanır (aşağıda helper ile client enjekte edilir)
    res = asyncio.run(path_probe._probe_with_transport("x.com", _mk(routes)))  # test-yardımcı
    paths=[f["path"] for f in res["findings"]]
    assert "/symfony/config/databases.yml" in paths
    assert res["findings"][0]["severity"]=="critical"
```
**Implementasyon notu:** Testin `client` enjekte edebilmesi için küçük bir iç yardımcı
`_probe_with_transport(host, transport, **kw)` eklenir (üretimde kullanılmaz; sadece HTTP'yi mocklamak
için `AsyncClient(transport=...)` kurar ve mevcut akışı çağırır). Önce-değer sıralaması `_SEVERITY_ORDER`
+ kaynak öncelik ağırlığı (curated/memory > template > llm > evidence) ile.

### Task 5: Genel sır-maskeleme catch-all + K1 regression

**Files:** Modify `_redact_snippet` (path_probe.py); genişlet `test_path_probe_symfony.py`

**Produces:** ENV + YAML maskesine ek: genel `password/token/secret/api_key` içeren satır/JSON değerleri
maskelenir (LLM/evidence kaynaklı yeni yol sınıfları ham sır sızdırmasın).
```python
def test_json_sir_maskesi():
    from pipeline.path_probe import _redact_snippet
    s=_redact_snippet("/x.json", '{"api_key":"AKIA123SECRET","host":"db.x"}')
    assert "AKIA123SECRET" not in s and "db.x" in s
```

**FAZ K1 çıkış kriteri:** databases.yml sınıfı LLM/DB olmadan yakalanıyor; `apps/api/...` üretiliyor;
kanıttan yol türüyor; kritik yol bütçe dolsa da ilk problanıyor; tüm K1 testleri geçiyor.

---

## FAZ K2 — LLM istihbarat subayı (opsiyonel, flag arkasında)

### Task 6: `path_intel.suggest_paths_llm` + sanitize/clamp

**Files:** Create `orchestrator/pipeline/path_intel.py`; Test `pipeline/test_path_intel.py`

**Produces:**
- `_sanitize_candidate(raw: dict) -> Optional[5-tuple]` (path regex `^/[\w\-./~%]+$`, `://` red,
  severity/category enum clamp, signature normalize, source="llm").
- `async suggest_paths_llm(fingerprint: dict, *, llm_call=None) -> List[5-tuple]` (≤30, dedup;
  `llm_call` enjekte edilebilir → test için; None ise `resolve_ai_service_default`+thinking KAPALI;
  her hata → `[]`).

**Test (llm_call fake ile — gerçek LLM YOK):**
```python
import asyncio
from pipeline.path_intel import _sanitize_candidate, suggest_paths_llm
def test_sanitize_reddi():
    assert _sanitize_candidate({"path":"http://evil/x"}) is None       # cross-host
    assert _sanitize_candidate({"path":"/a b"}) is None                 # geçersiz
    row=_sanitize_candidate({"path":"/c.dist","category":"garbage","severity":"ULTRA",
                             "signature":{"must_contain_any":["x"]}})
    assert row[1] in {"config_exposure","info_disclosure"}  # clamp
    assert row[2] in {"critical","high","medium","low","info"}
    assert row[3]=="signature" and row[4]["source"]=="llm"
def test_suggest_fallback_bos():
    async def boom(*a,**k): raise RuntimeError("no provider")
    assert asyncio.run(suggest_paths_llm({"tech":[]}, llm_call=boom)) == []
def test_suggest_ust_sinir():
    async def many(*a,**k): return [{"path":f"/p{i}","signature":{"must_contain_any":["x"]}} for i in range(100)]
    assert len(asyncio.run(suggest_paths_llm({}, llm_call=many))) <= 30
```

### Task 7: `_dispatch_pathprobe` + redteam canlı modda K2 enjeksiyonu (flag)

**Files:** Modify `scan_pipeline_v2.py:1999-2083`, `redteam_proxy.py`

**Produces:** `PATHPROBE_LLM_INTEL` (varsayılan "0") açıksa: fingerprint topla → `suggest_paths_llm`
→ `probe_sensitive_paths(extra_paths=...)`. Kapalıyken çağrı hiç yapılmaz (davranış aynı). Fingerprint
kaynağı: ilk hafif `_fingerprint_tech` çağrısı (dispatcher zaten tech_hints'e sahip).

**Test:** Flag kapalı → `suggest_paths_llm` çağrılmıyor (monkeypatch sayaç). Flag açık + fake →
`extra_paths` prober'a geçiyor. (Dispatcher testi ağır; en az flag-gating birim testi.)

---

## FAZ K3 — Öğrenme döngüsü

### Task 8: `path_memory` oku/yaz/birleştir (fake db)

**Files:** Create `orchestrator/pipeline/path_memory.py`; Test `pipeline/test_path_memory.py`

**Produces (db enjekte — test için fake collection):**
- `load_learned_paths(db, techs: List[str], *, cap=50) -> List[5-tuple]` (enabled + (tech eşleşen | []),
  confidence sıralı, source="memory").
- `record_findings(db, findings: List[dict], target: str)` (güçlü-validator/baseline-geçen upsert;
  hit_count++, targets, last_seen; ≥2 hedef → tech=[] terfi; kör 200 yazılmaz).
- `learn_path_manual(db, path, category, severity, signature=None, tech=None)` (source="manual_report",
  confidence yüksek, enabled).

**Test (fake in-memory collection):**
```python
from pipeline.path_memory import load_learned_paths, record_findings, learn_path_manual
class FakeCol:
    def __init__(self): self.docs=[]
    def find(self,q): return [d for d in self.docs if all(d.get(k)==v for k,v in q.items() if not isinstance(v,dict))]
    def update_one(self,f,u,upsert=False):
        for d in self.docs:
            if d.get("path")==f.get("path"): d.update(u.get("$set",{})); d["hit_count"]=d.get("hit_count",0)+u.get("$inc",{}).get("hit_count",0); return
        if upsert: nd={**f,**u.get("$set",{})}; nd["hit_count"]=u.get("$inc",{}).get("hit_count",0); self.docs.append(nd)
def test_manuel_giris_sonra_yuklenir():
    c=FakeCol(); learn_path_manual(c,"/symfony/config/databases.yml","credential_exposure","critical")
    rows=load_learned_paths(c,["symfony"]); assert any(r[0]=="/symfony/config/databases.yml" for r in rows)
def test_kor_200_yazilmaz():
    c=FakeCol(); record_findings(c,[{"path":"/x","validator":"generic","severity":"low","category":"info_disclosure"}],"t")
    assert c.docs==[]   # generic (güçlü değil, baseline bilgisi yok) yazılmaz
```

### Task 9: Dispatcher K3 kablolaması + `POST /redteam/learn-path`

**Files:** Modify `scan_pipeline_v2.py` (`_dispatch_pathprobe`), `redteam_proxy.py`

**Produces:** `PATHPROBE_MEMORY` (varsayılan "0") açıksa: başta `load_learned_paths` → `extra_paths`e
kat; sonda `record_findings`. `POST /api/redteam/learn-path` (admin-only) → `learn_path_manual`.
MongoClient mevcut singleton'dan alınır. Kapalıyken davranış aynı.

**Test:** `learn-path` endpoint payload → `learn_path_manual` çağrısı (route birim testi / manuel curl).

---

## Self-Review (spec kapsamı)
- Teşhis #1 (yol yok) → Task 2 (şablon) + Task 8/9 (manuel giriş). ✔
- Teşhis #3 (recon symfony kaçırır) → Task 4 (fingerprint→aile). ✔
- Teşhis #4 (bütçe iptali) → Task 4 (önce-değer sıralama). ✔
- K2 güvenlik korkulukları → Task 6 (sanitize/clamp/fallback). ✔
- K3 kirlenme korkulukları → Task 8 (kör-200 yazılmaz, terfi). ✔
- Determinizm/flag → Task 7/9 (flag kapalı = bugünkü davranış). ✔
- Maskeleme → Task 5. ✔

## Yürütme
Inline (subagent YOK — kullanıcı istemedi), TDD, **commit YOK** (kullanıcı onayına kadar). Her task
sonunda ilgili test scripti çalıştırılıp PASS doğrulanır.
