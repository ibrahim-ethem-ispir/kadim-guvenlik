"""Türkçe: Symfony config-ifşası validator/maskeleme/pivot birim testleri (SAF — I/O yok).

Kök neden: rakip ekip portal.example-corp.com/symfony/config/databases.yml ifşasını buldu,
bizim katalog bu yolu hiç problamıyordu. Eklenen symfony_databases/symfony_parameters
validator'ları + YAML sır maskesi + YAML host pivotu burada sabitlenir (regression).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pipeline.path_probe import (
    _validate_symfony_databases, _validate_symfony_parameters,
    _redact_snippet, _extract_pivot_hints, SENSITIVE_PATHS, _STRONG_VALIDATORS,
    _VALIDATORS,
)

_SYMFONY_DB = """all:
  propel:
    class: sfPropelDatabase
    param:
      phptype: mysql
      hostspec: db.example.local
      database: portal_db
      username: portal_user
      password: Sup3rS3cret
"""

_SYMFONY_DB_DSN = """all:
  doctrine:
    class: sfDoctrineDatabase
    param:
      dsn: mysql:host=db.internal;dbname=portal
      username: app
      password: gizli123
"""

_PARAMETERS_YML = """parameters:
    database_driver: pdo_mysql
    database_host: 10.20.30.40
    database_name: portal
    database_user: root
    database_password: P@ssw0rd!
    secret: abcdef123456
"""

_SOFT404_HTML = "<!DOCTYPE html><html><head><title>Sayfa bulunamadı</title></head><body>404</body></html>"

_DOCKER_COMPOSE = """version: '3'
services:
  web:
    image: nginx
    ports:
      - "80:80"
"""


def test_symfony_databases_yolu_statik_katalogda():
    """Kök-neden regression: databases.yml statik katalogda OLMALI (recon tespitine
    bağımlı kalırsa Symfony'yi tanıyamayan hedeflerde yine kaçar)."""
    paths = {row[0] for row in SENSITIVE_PATHS}
    assert "/symfony/config/databases.yml" in paths
    assert "/config/databases.yml" in paths


def test_symfony_databases_validator_guclu_listede():
    """Güçlü validator: soft-404 baseline elemesi bu sınıfa UYGULANMAMALI."""
    assert "symfony_databases" in _STRONG_VALIDATORS
    assert "symfony_databases" in _VALIDATORS
    assert "symfony_parameters" in _VALIDATORS


def test_symfony_databases_gercek_govde_dogrulanir():
    assert _validate_symfony_databases(200, "text/plain", _SYMFONY_DB) is True
    assert _validate_symfony_databases(200, "text/plain", _SYMFONY_DB_DSN) is True


def test_symfony_databases_soft404_elenir():
    assert _validate_symfony_databases(200, "text/html", _SOFT404_HTML) is False
    # Alakasız YAML (docker-compose) motor+kimlik imzası taşımaz → elenir.
    assert _validate_symfony_databases(200, "text/plain", _DOCKER_COMPOSE) is False


def test_symfony_parameters_dogrulama():
    assert _validate_symfony_parameters(200, "text/plain", _PARAMETERS_YML) is True
    assert _validate_symfony_parameters(200, "text/html", _SOFT404_HTML) is False
    assert _validate_symfony_parameters(200, "text/plain", _DOCKER_COMPOSE) is False


def test_yaml_sirleri_snippetta_maskelenir():
    """DB parolası/kullanıcısı Mongo'ya/rapora HAM yazılmamalı (sır sızıntısı)."""
    snip = _redact_snippet("/symfony/config/databases.yml", _SYMFONY_DB)
    assert "Sup3rS3cret" not in snip
    assert "portal_user" not in snip
    # Maske uzunluk-bilgisi taşır (kanıt değeri korunur), host AÇIK kalır (pivot hedefi).
    assert "***11***" in snip
    assert "db.example.local" in snip


def test_yaml_host_pivotu_cikarilir():
    """databases.yml'deki hostspec iç altyapı pivot hedefidir (zincir saldırı)."""
    hints = _extract_pivot_hints(_SYMFONY_DB)
    assert "db.example.local" in hints["hosts"]
    # dsn içi host=... yakalanır.
    hints2 = _extract_pivot_hints(_SYMFONY_DB_DSN)
    assert "db.internal" in hints2["hosts"]
    # localhost pivot değeri taşımaz.
    hints3 = _extract_pivot_hints("all:\n  propel:\n    hostspec: localhost\n    username: x\n    password: y")
    assert "localhost" not in hints3["hosts"]


def test_json_sir_maskesi():
    """K1 Task5: JSON tarzı sırlar (config/*.json, actuator/env) HAM yazılmamalı. Host gibi
    yapısal (pivot hedefi) alanlar AÇIK kalır — kanıt/zincir değeri korunur."""
    s = _redact_snippet("/config/production.json",
                        '{"api_key":"AKIA123SECRET","db_password":"p4ss","host":"db.internal"}')
    assert "AKIA123SECRET" not in s
    assert "p4ss" not in s
    assert "***13***" in s          # api_key değeri maskelendi (uzunluk kanıtı)
    assert "db.internal" in s       # host pivot hedefi açık


def main():
    tests = [
        test_symfony_databases_yolu_statik_katalogda,
        test_symfony_databases_validator_guclu_listede,
        test_symfony_databases_gercek_govde_dogrulanir,
        test_symfony_databases_soft404_elenir,
        test_symfony_parameters_dogrulama,
        test_yaml_sirleri_snippetta_maskelenir,
        test_yaml_host_pivotu_cikarilir,
        test_json_sir_maskesi,
    ]
    for t in tests:
        t()
        print(f"[OK] {t.__name__}")
    print("\nTüm testler geçti.")


if __name__ == "__main__":
    main()
