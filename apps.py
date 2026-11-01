"""
Synapse Fraud Prevention — MVP Antifraude-as-a-Service (FaaS) para Pix com IA
=============================================================================
Compatível com:
- Streamlit in Snowflake ("USER$izaque.brito".PUBLIC.STBE926F279416E6D4C1FAF8F132346F1FF2873093)
  * Funciona nativamente COM ou SEM o pacote `plotly` habilitado no Snowflake
    (Motor Gráfico Multi-Backend: Plotly -> Altair -> SVG/HTML Nativo).
- Streamlit Local / Docker / GCP Cloud Run

Arquitetura baseada em princípios SOLID e Design Patterns:
- AuthenticationService (SRP): Autenticação com PBKDF2-SHA256 e resolução de RBAC no servidor.
- OnboardingTenantService (SRP/Factory): Jornada B2B com emissão de API Token (syn_live_ / syn_sandbox_).
- PixScoringEngine (OCP/Strategy): Motor de Score 0-99 focado exclusivamente em Golpes Pix.
- FeatureStoreRepository (Adapter/DIP): Híbrido Snowflake Snowpark + CSV Upload + In-Memory Generator.
- ChartRenderer (Strategy/Adapter): Renderização resiliente de Donut, Barras Empilhadas, Clusters e Mapa
  (suporta Plotly, Altair nativo do Snowflake e SVG fallback sem quebrar se `plotly` não estiver instalado).
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

try:
    import plotly.express as px
    import plotly.graph_objects as go

    HAS_PLOTLY = True
except Exception:  # pragma: no cover
    px = None
    go = None
    HAS_PLOTLY = False

try:
    import altair as alt

    HAS_ALTAIR = True
except Exception:  # pragma: no cover
    alt = None
    HAS_ALTAIR = False

try:
    import streamlit as st
except Exception:  # pragma: no cover
    st = None

# Tentativa de conexão nativa com Snowflake (Streamlit in Snowflake - SiS)
HAS_SNOWFLAKE_SESSION = False
_SNOWFLAKE_SESSION = None
try:
    from snowflake.snowpark.context import get_active_session

    _SNOWFLAKE_SESSION = get_active_session()
    HAS_SNOWFLAKE_SESSION = True
except Exception:
    HAS_SNOWFLAKE_SESSION = False


# ==============================================================================
# 1. CONSTANTES DE DOMÍNIO PIX, GEOGRAFIA & BACEN (CPF x DDD x UF)
# ==============================================================================

CPF_REGION_DDD_MAP: Dict[int, List[int]] = {
    1: [61, 62, 64, 65, 66, 67, 63],  # DF, GO, MT, MS, TO
    2: [91, 93, 94, 92, 97, 68, 96, 69, 95],  # AC, AM, AP, PA, RO, RR
    3: [85, 88, 98, 99, 86, 89],  # CE, MA, PI
    4: [82, 83, 81, 87, 84],  # AL, PB, PE, RN
    5: [71, 73, 74, 75, 77, 79],  # BA, SE
    6: [31, 32, 33, 34, 35, 37, 38],  # MG
    7: [27, 28, 21, 22, 24],  # ES, RJ
    8: [11, 12, 13, 14, 15, 16, 17, 18, 19],  # SP
    9: [41, 42, 43, 44, 45, 46, 47, 48, 49],  # PR, SC
    0: [51, 53, 54, 55],  # RS
}

DDD_TO_UF_COORDS: Dict[int, Tuple[str, str, float, float]] = {
    11: ("SP", "São Paulo - Capital", -23.5505, -46.6333),
    19: ("SP", "Campinas / Interior SP", -22.9099, -47.0626),
    21: ("RJ", "Rio de Janeiro", -22.9068, -43.1729),
    27: ("ES", "Vitória", -20.3155, -40.3128),
    31: ("MG", "Belo Horizonte", -19.9167, -43.9345),
    41: ("PR", "Curitiba", -25.4284, -49.2733),
    48: ("SC", "Florianópolis", -27.5954, -48.5480),
    51: ("RS", "Porto Alegre", -30.0346, -51.2177),
    61: ("DF", "Brasília", -15.7975, -47.8919),
    62: ("GO", "Goiânia", -16.6869, -49.2648),
    71: ("BA", "Salvador", -12.9777, -38.5016),
    81: ("PE", "Recife", -8.0476, -34.8770),
    85: ("CE", "Fortaleza", -3.7319, -38.5267),
    91: ("PA", "Belém", -1.4558, -48.4902),
    92: ("AM", "Manaus", -3.1190, -60.0217),
}

PIX_SCAM_TYPOLOGIES: List[str] = [
    "Transação Legítima",
    "Mule Account (Conta Laranja)",
    "Account Takeover (Invasão ATO)",
    "QR Code Falso / Eng. Social",
    "Falsa Central / Mão Fantasma",
    "Pulverização / Drop Rápido",
]

DECISION_POLICIES: List[str] = [
    "APROVADO",
    "MFA / STEP-UP",
    "REVISÃO MANUAL",
    "BLOQUEIO CAUTELAR (72h)",
    "REPROVADO / ABRIR MED",
]

DECISION_COLOR_MAP: Dict[str, str] = {
    "APROVADO": "#00E676",
    "MFA / STEP-UP": "#38BDF8",
    "REVISÃO MANUAL": "#FBBF24",
    "BLOQUEIO CAUTELAR (72h)": "#F97316",
    "REPROVADO / ABRIR MED": "#EF4444",
}

TYPOLOGY_COLOR_MAP: Dict[str, str] = {
    "Transação Legítima": "#00E676",
    "Mule Account (Conta Laranja)": "#EF4444",
    "Account Takeover (Invasão ATO)": "#F97316",
    "QR Code Falso / Eng. Social": "#FBBF24",
    "Falsa Central / Mão Fantasma": "#A855F7",
    "Pulverização / Drop Rápido": "#38BDF8",
}


# ==============================================================================
# 2. SEGURANÇA & AUTENTICAÇÃO RBAC (SOLID: Single Responsibility Principle)
# ==============================================================================


@dataclass(frozen=True)
class AuthenticatedUser:
    username: str
    email: str
    full_name: str
    role: str  # "Administrador", "Analista", "Auditor"
    tenant_id: str
    permissions: Tuple[str, ...]

    def has_permission(self, perm: str) -> bool:
        return perm in self.permissions or "all" in self.permissions


class AuthenticationService:
    """
    Serviço de Autenticação e RBAC.
    Corrige a vulnerabilidade de login sem verificação de senha e elimina
    a auto-declaração do perfil 'Administrador' na interface.
    """

    _SALT = b"synapse_pix_faas_salt_v1"

    @classmethod
    def _hash_password(cls, password: str) -> str:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), cls._SALT, 100_000
        ).hex()

    @classmethod
    def _get_user_directory(cls) -> Dict[str, Dict[str, Any]]:
        admin_pwd = os.getenv("SYNAPSE_ADMIN_PASSWORD", "Synapse@Admin2026")
        analyst_pwd = os.getenv("SYNAPSE_ANALYST_PASSWORD", "Synapse@Analista2026")
        auditor_pwd = os.getenv("SYNAPSE_AUDITOR_PASSWORD", "Synapse@Auditor2026")
        return {
            "admin@synapse.io": {
                "username": "izaque.brito",
                "full_name": "Izaque Brito (Head of Fraud & Admin)",
                "role": "Administrador",
                "tenant_id": "TENANT-SYNAPSE-MASTER",
                "password_hash": cls._hash_password(admin_pwd),
                "permissions": (
                    "all",
                    "calibrate_weights",
                    "manage_onboarding",
                    "issue_api_token",
                    "execute_automations",
                    "export_med",
                    "view_cockpit",
                ),
            },
            "analista@synapse.io": {
                "username": "analista.mesa",
                "full_name": "Marina Costa (Analista Sênior Antifraude Pix)",
                "role": "Analista",
                "tenant_id": "TENANT-SYNAPSE-MASTER",
                "password_hash": cls._hash_password(analyst_pwd),
                "permissions": (
                    "execute_automations",
                    "export_med",
                    "view_cockpit",
                ),
            },
            "auditor@synapse.io": {
                "username": "auditor.bacen",
                "full_name": "Carlos Mendes (Compliance & Auditoria BACEN/MED)",
                "role": "Auditor",
                "tenant_id": "TENANT-SYNAPSE-MASTER",
                "password_hash": cls._hash_password(auditor_pwd),
                "permissions": ("view_cockpit", "export_med"),
            },
        }

    @classmethod
    def authenticate(cls, identifier: str, password: str) -> Optional[AuthenticatedUser]:
        if not identifier or not password:
            return None
        clean_id = identifier.strip().lower()
        directory = cls._get_user_directory()

        matched_email = None
        if clean_id in directory:
            matched_email = clean_id
        else:
            for email_key, record in directory.items():
                if record["username"].lower() == clean_id:
                    matched_email = email_key
                    break

        if not matched_email:
            return None

        user_record = directory[matched_email]
        candidate_hash = cls._hash_password(password)
        if not hmac.compare_digest(candidate_hash, user_record["password_hash"]):
            return None

        return AuthenticatedUser(
            username=user_record["username"],
            email=matched_email,
            full_name=user_record["full_name"],
            role=user_record["role"],
            tenant_id=user_record["tenant_id"],
            permissions=tuple(user_record["permissions"]),
        )


# ==============================================================================
# 3. ONBOARDING B2B & GESTÃO DE TOKENS API FaaS (SOLID: Factory / Service)
# ==============================================================================


@dataclass
class B2BTenantConfig:
    tenant_id: str
    cnpj: str
    company_name: str
    ispb_code: str
    segment: str
    monthly_pix_volume: int
    contact_email: str
    webhook_url: str
    threshold_mfa: int = 35
    threshold_review: int = 60
    threshold_block_72h: int = 75
    threshold_med: int = 88
    auto_block_72h: bool = True
    auto_open_med: bool = True
    auto_mfa_stepup: bool = True
    api_token_live: str = ""
    api_token_sandbox: str = ""
    token_fingerprint: str = ""
    created_at: str = ""
    status: str = "ACTIVE"


class OnboardingTenantService:
    """
    Gerencia o Onboarding B2B de instituições financeiras, fintechs e PSPs
    no Antifraude-as-a-Service (FaaS), habilitando o Token para consumo via API.
    """

    @staticmethod
    def validate_cnpj_format(cnpj: str) -> bool:
        digits = "".join(ch for ch in (cnpj or "") if ch.isdigit())
        return len(digits) == 14

    @classmethod
    def provision_tenant_and_tokens(
        cls,
        cnpj: str,
        company_name: str,
        ispb_code: str,
        segment: str,
        monthly_pix_volume: int,
        contact_email: str,
        webhook_url: str,
        threshold_mfa: int = 35,
        threshold_review: int = 60,
        threshold_block_72h: int = 75,
        threshold_med: int = 88,
        auto_block_72h: bool = True,
        auto_open_med: bool = True,
        auto_mfa_stepup: bool = True,
    ) -> B2BTenantConfig:
        digits = "".join(ch for ch in cnpj if ch.isdigit())
        if len(digits) != 14:
            raise ValueError("CNPJ inválido. Informe os 14 dígitos numéricos.")
        if not company_name or len(company_name.strip()) < 3:
            raise ValueError("Razão Social da empresa é obrigatória.")
        if not (0 < threshold_mfa < threshold_review < threshold_block_72h < threshold_med <= 99):
            raise ValueError(
                "Os limiares da Política de Decisão devem ser estritamente crescentes (ex: 35 < 60 < 75 < 88)."
            )

        tenant_hash = hashlib.sha256(f"{digits}:{company_name}".encode("utf-8")).hexdigest()[:8].upper()
        tenant_id = f"SYN-B2B-{tenant_hash}"

        raw_live_secret = secrets.token_urlsafe(24).replace("-", "").replace("_", "")[:28]
        raw_sbx_secret = secrets.token_urlsafe(24).replace("-", "").replace("_", "")[:28]

        api_token_live = f"syn_live_{tenant_hash.lower()}_{raw_live_secret}"
        api_token_sandbox = f"syn_sandbox_{tenant_hash.lower()}_{raw_sbx_secret}"
        token_fp = hashlib.sha256(api_token_live.encode("utf-8")).hexdigest()[:16]

        return B2BTenantConfig(
            tenant_id=tenant_id,
            cnpj=digits,
            company_name=company_name.strip(),
            ispb_code=(ispb_code or "00000000").strip(),
            segment=segment,
            monthly_pix_volume=int(monthly_pix_volume),
            contact_email=contact_email.strip(),
            webhook_url=webhook_url.strip() or "https://api.instituicao.com.br/v1/webhooks/synapse-pix",
            threshold_mfa=int(threshold_mfa),
            threshold_review=int(threshold_review),
            threshold_block_72h=int(threshold_block_72h),
            threshold_med=int(threshold_med),
            auto_block_72h=bool(auto_block_72h),
            auto_open_med=bool(auto_open_med),
            auto_mfa_stepup=bool(auto_mfa_stepup),
            api_token_live=api_token_live,
            api_token_sandbox=api_token_sandbox,
            token_fingerprint=token_fp,
            created_at=dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            status="ACTIVE",
        )


# ==============================================================================
# 4. MOTOR DE SCORE PIX (0-99), POLÍTICAS DE DECISÃO, CLUSTERS E AUTOMAÇÕES IA
# ==============================================================================


@dataclass
class PixRiskWeights:
    """Pesos calibráveis pelo Administrador para o Motor Híbrido Pix (Regras + IA)."""

    w_value_rupture: int = 25
    w_cpf_ddd_mismatch: int = 20
    w_night_window: int = 15
    w_velocity_24h: int = 20
    w_device_emulator_vpn: int = 25
    w_new_pix_key: int = 18
    w_typing_cadence_rat: int = 20
    w_geo_distance: int = 15
    w_fan_in_mule: int = 22


class PixScoringEngine:
    """
    Motor de Score Antifraude-as-a-Service focado 100% em Golpes Pix.
    Processa lotes CSV, tabelas Snowflake ou transações individuais em tempo real,
    calculando Score (0-99), Política de Decisão, Tipologia de Golpe, Cluster e
    Recomendações acionáveis de IA.
    """

    REQUIRED_DEFAULTS: Dict[str, Any] = {
        "txId": "PIX-UNSPECIFIED",
        "accountId": "ACC-1000",
        "originBank": "Nubank",
        "destBank": "Mercado Pago",
        "pixKeyType": "CPF",
        "pixKey": "***.456.789-**",
        "valor": 500.0,
        "avgValue30d": 250.0,
        "hour": 14,
        "txCount24h": 2,
        "destAccountAgeDays": 180,
        "uniqueSenders24h": 1,
        "cpf_9th_digit": 8,
        "ddd_telefone": 11,
        "geoDistanceKm": 8.0,
        "deviceStatus": "Trusted",
        "device_fingerprint_id": "DFP-88A19C02",
        "os_browser": "Android 14 / App Nativo v8.4",
        "ip_address": "177.84.120.14",
        "asn_isp": "AS28573 Claro NXT",
        "vpn_proxy_tor": False,
        "gps_spoofing": False,
        "remote_access_rat": False,
        "typing_cadence_score": 92,
        "network_latency_ms": 28,
        "isFraud": 0,
    }

    @staticmethod
    def check_cpf_ddd_consistency(cpf_digit: int, ddd: int) -> bool:
        valid_ddds = CPF_REGION_DDD_MAP.get(int(cpf_digit) % 10, [])
        return int(ddd) in valid_ddds

    @classmethod
    def normalize_dataframe(cls, df_raw: pd.DataFrame) -> pd.DataFrame:
        df = df_raw.copy()

        # Mapeamento case-insensitive (ex: Snowflake UPPERCASE)
        lower_map = {c.lower(): c for c in df.columns}
        for c_col in cls.REQUIRED_DEFAULTS:
            if c_col not in df.columns and c_col.lower() in lower_map:
                df[c_col] = df[lower_map[c_col.lower()]]

        column_aliases = {
            "id": "txId",
            "tx_id": "txId",
            "transaction_id": "txId",
            "conta": "accountId",
            "account_id": "accountId",
            "valor_brl": "valor",
            "amount": "valor",
            "value": "valor",
            "hora": "hour",
            "frequencia": "txCount24h",
            "velocity_24h": "txCount24h",
            "distancia_km": "geoDistanceKm",
            "distance_km": "geoDistanceKm",
            "banco_origem": "originBank",
            "banco_destino": "destBank",
            "tipo_chave": "pixKeyType",
            "chave_pix": "pixKey",
        }
        for src_col, target_col in column_aliases.items():
            if src_col in df.columns and target_col not in df.columns:
                df[target_col] = df[src_col]

        n = len(df)
        rng = np.random.default_rng(42)

        if "txId" not in df.columns:
            df["txId"] = [f"PIX-{100000 + i}" for i in range(n)]
        if "accountId" not in df.columns:
            df["accountId"] = [f"ACC-{2000 + (i % 90)}" for i in range(n)]
        if "valor" not in df.columns:
            df["valor"] = np.round(rng.exponential(scale=1200.0, size=n) + 50.0, 2)
        if "avgValue30d" not in df.columns:
            df["avgValue30d"] = np.round(np.maximum(df["valor"] * rng.uniform(0.15, 0.95, size=n), 80.0), 2)
        if "hour" not in df.columns:
            df["hour"] = rng.integers(0, 24, size=n)
        if "txCount24h" not in df.columns:
            df["txCount24h"] = rng.integers(1, 25, size=n)
        if "destAccountAgeDays" not in df.columns:
            if "chave_nova" in df.columns:
                df["destAccountAgeDays"] = np.where(df["chave_nova"].astype(int) == 1, 2, 240)
            else:
                df["destAccountAgeDays"] = rng.choice([1, 3, 7, 45, 180, 420], size=n, p=[0.08, 0.10, 0.12, 0.20, 0.30, 0.20])
        if "uniqueSenders24h" not in df.columns:
            df["uniqueSenders24h"] = np.where(df["destAccountAgeDays"] <= 7, rng.integers(3, 19, size=n), rng.integers(1, 4, size=n))
        if "cpf_9th_digit" not in df.columns:
            df["cpf_9th_digit"] = rng.integers(0, 10, size=n)
        if "ddd_telefone" not in df.columns:
            df["ddd_telefone"] = rng.choice(list(DDD_TO_UF_COORDS.keys()), size=n)
        if "geoDistanceKm" not in df.columns:
            df["geoDistanceKm"] = np.round(rng.exponential(scale=85.0, size=n), 1)
        if "deviceStatus" not in df.columns:
            if "dispositivo_novo" in df.columns:
                df["deviceStatus"] = np.where(df["dispositivo_novo"].astype(int) == 1, "New_Device", "Trusted")
            else:
                df["deviceStatus"] = rng.choice(
                    ["Trusted", "New_Device", "Emulator_Root", "VPN_Proxy"],
                    size=n,
                    p=[0.68, 0.16, 0.08, 0.08],
                )

        for col, default_val in cls.REQUIRED_DEFAULTS.items():
            if col not in df.columns:
                df[col] = default_val

        ufs, cities, lats, lons = [], [], [], []
        for idx, ddd_val in enumerate(df["ddd_telefone"]):
            ddd_int = int(ddd_val) if pd.notna(ddd_val) else 11
            uf, city, lat, lon = DDD_TO_UF_COORDS.get(ddd_int, ("SP", "São Paulo", -23.5505, -46.6333))
            ufs.append(uf)
            cities.append(city)
            jitter_lat = ((idx * 17) % 100 - 50) * 0.012
            jitter_lon = ((idx * 31) % 100 - 50) * 0.012
            lats.append(round(lat + jitter_lat, 4))
            lons.append(round(lon + jitter_lon, 4))

        df["uf"] = ufs
        df["city"] = cities
        df["lat"] = lats
        df["lon"] = lons

        return df

    @classmethod
    def score_dataframe(
        cls,
        df_input: pd.DataFrame,
        weights: Optional[PixRiskWeights] = None,
        tenant_policy: Optional[B2BTenantConfig] = None,
    ) -> pd.DataFrame:
        w = weights or PixRiskWeights()
        t_mfa = tenant_policy.threshold_mfa if tenant_policy else 35
        t_rev = tenant_policy.threshold_review if tenant_policy else 60
        t_blk = tenant_policy.threshold_block_72h if tenant_policy else 75
        t_med = tenant_policy.threshold_med if tenant_policy else 88

        df = cls.normalize_dataframe(df_input)

        scores: List[int] = []
        decisions: List[str] = []
        typologies: List[str] = []
        clusters: List[str] = []
        recommendations: List[str] = []
        automations: List[str] = []
        reasons_list: List[str] = []
        cpf_ddd_valid_list: List[bool] = []
        latencies_ms: List[int] = []

        for idx, row in df.iterrows():
            pts = 0.0
            reasons: List[str] = []

            valor = float(row["valor"])
            avg_30d = max(float(row["avgValue30d"]), 1.0)
            ratio_val = valor / avg_30d
            hour = int(row["hour"])
            tx_24h = int(row["txCount24h"])
            dest_age = int(row["destAccountAgeDays"])
            unique_senders = int(row["uniqueSenders24h"])
            cpf_dig = int(row["cpf_9th_digit"])
            ddd = int(row["ddd_telefone"])
            geo_km = float(row["geoDistanceKm"])
            dev_status = str(row["deviceStatus"])
            vpn_flag = bool(row["vpn_proxy_tor"]) or dev_status == "VPN_Proxy"
            gps_spoof = bool(row["gps_spoofing"])
            rat_flag = bool(row["remote_access_rat"])
            cadence = int(row["typing_cadence_score"])

            if ratio_val >= 4.0 and valor >= 1500:
                pts += w.w_value_rupture
                reasons.append(f"Ruptura severa de valor ({ratio_val:.1f}x acima da média 30d)")
            elif ratio_val >= 2.2 and valor >= 800:
                pts += w.w_value_rupture * 0.55
                reasons.append(f"Valor atípico ({ratio_val:.1f}x da média habitual)")

            cpf_ddd_ok = cls.check_cpf_ddd_consistency(cpf_dig, ddd)
            cpf_ddd_valid_list.append(cpf_ddd_ok)
            if not cpf_ddd_ok:
                pts += w.w_cpf_ddd_mismatch
                reasons.append(f"Conflito Geográfico CPF (Região {cpf_dig}) vs DDD ({ddd})")

            is_night = hour >= 20 or hour <= 5
            if is_night and valor >= 800:
                pts += w.w_night_window
                reasons.append(f"Janela Noturna Pix ({hour:02d}h) com valor sensível")

            if tx_24h >= 12:
                pts += w.w_velocity_24h
                reasons.append(f"Alta velocidade transacional ({tx_24h} Pix em 24h)")
            elif tx_24h >= 7:
                pts += w.w_velocity_24h * 0.5
                reasons.append(f"Frequência elevada ({tx_24h} Pix/24h)")

            if dev_status == "Emulator_Root":
                pts += w.w_device_emulator_vpn
                reasons.append("Device Fingerprint: Emulador / Root detectado pelo SDK")
            elif vpn_flag or gps_spoof:
                pts += w.w_device_emulator_vpn * 0.85
                reasons.append("Network Footprint: Proxy/VPN anônimo ou GPS Spoofing ativo")
            elif dev_status == "New_Device":
                pts += w.w_device_emulator_vpn * 0.50
                reasons.append("Dispositivo não reconhecido (1º acesso na conta)")

            if dest_age <= 5:
                pts += w.w_new_pix_key
                reasons.append(f"Chave Pix destino recém-criada ({dest_age} dias)")
            if unique_senders >= 8 and dest_age <= 15:
                pts += w.w_fan_in_mule
                reasons.append(f"Padrão Conta Laranja (Mule): {unique_senders} pagadores distintos p/ chave nova")

            if rat_flag or cadence < 45:
                pts += w.w_typing_cadence_rat
                reasons.append(f"Anomalia de Sessão SDK: Cadência {cadence}/100 ou Acesso Remoto (RAT)")

            if geo_km >= 350:
                pts += w.w_geo_distance
                reasons.append(f"Deslocamento geográfico extremo ({geo_km:.0f} km do perímetro habitual)")

            score = int(min(max(round(pts), 2), 99))
            scores.append(score)

            if score >= t_med:
                decision = "REPROVADO / ABRIR MED"
                rec = (
                    "Bloquear liquidação imediatamente, protocolar Mecanismo Especial de Devolução (MED) "
                    "e sinalizar chave destino no DICT como suspeita de fraude."
                )
                auto_act = "WEBHOOK_BLOCK + OPEN_BACEN_MED + DICT_FRAUD_MARKER"
            elif score >= t_blk:
                decision = "BLOQUEIO CAUTELAR (72h)"
                rec = (
                    "Retenção Cautelar de 72h (Resolução BCB nº 147). Notificar recebedor e acionar "
                    "análise forense de vínculo da conta destino."
                )
                auto_act = "HOLD_CAUTELAR_72H + NOTIFY_COMPLIANCE_QUEUE"
            elif score >= t_rev:
                decision = "REVISÃO MANUAL"
                rec = (
                    "Reter em fila prioritária da Mesa Antifraude com confirmação ativa via Push/WhatsApp "
                    "oficial da instituição."
                )
                auto_act = "ROUTE_TO_FRAUD_DESK + OUTBOUND_CONFIRMATION"
            elif score >= t_mfa:
                decision = "MFA / STEP-UP"
                rec = (
                    "Exigir Step-Up de Biometria Facial com Prova de Vida (Liveness 3D) antes de autorizar "
                    "a assinatura do Pix no SPI."
                )
                auto_act = "STEP_UP_FACIAL_LIVENESS_SDK"
            else:
                decision = "APROVADO"
                rec = "Fluxo frictionless aprovado em tempo real (SLA < 40ms). Sem fricção para o pagador."
                auto_act = "ALLOW_SPI_SETTLEMENT"

            decisions.append(decision)
            recommendations.append(rec)
            automations.append(auto_act)

            if score < t_mfa:
                typology = "Transação Legítima"
                cluster = "Cluster 0 — Operação Normal / Confiável"
            elif unique_senders >= 7 or (dest_age <= 7 and tx_24h >= 8):
                typology = "Mule Account (Conta Laranja)"
                cluster = "Cluster 1 — Anel de Contas Laranja (Mule Ring)"
            elif dev_status in ("Emulator_Root", "New_Device") and (is_night or geo_km >= 250):
                typology = "Account Takeover (Invasão ATO)"
                cluster = "Cluster 2 — Invasão de Conta (ATO / Device Anomaly)"
            elif rat_flag or cadence < 50:
                typology = "Falsa Central / Mão Fantasma"
                cluster = "Cluster 3 — Engenharia Social / RAT & Coação"
            elif tx_24h >= 12:
                typology = "Pulverização / Drop Rápido"
                cluster = "Cluster 1 — Anel de Contas Laranja (Mule Ring)"
            else:
                typology = "QR Code Falso / Eng. Social"
                cluster = "Cluster 3 — Engenharia Social / RAT & Coação"

            typologies.append(typology)
            clusters.append(cluster)
            reasons_list.append(" | ".join(reasons) if reasons else "Comportamento consistente com histórico de 30 dias")
            latencies_ms.append(int(row.get("network_latency_ms", 24)) + (idx % 11))

        df["riskScore"] = scores
        df["decision"] = decisions
        df["fraudTypology"] = typologies
        df["clusterName"] = clusters
        df["aiRecommendation"] = recommendations
        df["automationTrigger"] = automations
        df["reasons"] = reasons_list
        df["cpf_ddd_consistente"] = cpf_ddd_valid_list
        df["engineLatencyMs"] = latencies_ms
        df["periodWindow"] = np.where((df["hour"] >= 20) | (df["hour"] <= 5), "Noturno (20h-06h)", "Diurno (06h-20h)")

        return df


# ==============================================================================
# 5. REPOSITÓRIO DE DADOS / FEATURE STORE (Snowflake + CSV + Sintético Realista)
# ==============================================================================


class FeatureStoreRepository:
    @classmethod
    def load_from_snowflake_or_default(cls, n_samples: int = 360) -> Tuple[pd.DataFrame, str]:
        if HAS_SNOWFLAKE_SESSION and _SNOWFLAKE_SESSION is not None:
            try:
                sf_df = _SNOWFLAKE_SESSION.table("PIX_TRANSACTIONS_FEATURES").limit(1000).to_pandas()
                if not sf_df.empty:
                    sf_df.columns = [c.lower() for c in sf_df.columns]
                    return sf_df, "Snowflake Feature Store (PIX_TRANSACTIONS_FEATURES)"
            except Exception:
                pass
        return cls.generate_pix_dataset(n_samples), (
            "Snowflake Session Ativa (Dataset Calibrado Pix)"
            if HAS_SNOWFLAKE_SESSION
            else "Feature Store Sintética Calibrada (360 Pix)"
        )

    @staticmethod
    def generate_pix_dataset(n_samples: int = 350, seed: int = 42) -> pd.DataFrame:
        rng = np.random.default_rng(seed)
        banks = ["Nubank", "Itaú Unibanco", "Bradesco", "Banco do Brasil", "Santander", "Mercado Pago", "PicPay", "Banco Inter", "C6 Bank"]
        key_types = ["CPF", "CNPJ", "Celular", "E-mail", "Chave Aleatória (EVP)"]
        isps = ["AS28573 Claro NXT", "AS26599 Vivo Fibra", "AS26615 TIM Brasil", "AS16509 AWS Cloud (ASN Suspeito)", "AS14061 DigitalOcean Proxy"]
        os_list = [
            "Android 14 / App Nativo v8.4",
            "iOS 17.5 / iPhone 15 Pro",
            "Android 11 / Moto G (Rooted)",
            "Web Browser Chrome / Windows 11",
            "Android Emulator ( QEMU / BlueStacks )",
        ]
        ddd_keys = list(DDD_TO_UF_COORDS.keys())

        records: List[Dict[str, Any]] = []
        for i in range(n_samples):
            archetype_roll = rng.random()
            if archetype_roll < 0.58:
                valor = round(float(rng.uniform(45.0, 1400.0)), 2)
                avg30 = round(valor * float(rng.uniform(0.65, 1.35)), 2)
                hour = int(rng.integers(7, 20))
                tx24 = int(rng.integers(1, 5))
                dest_age = int(rng.integers(60, 720))
                senders = int(rng.integers(1, 3))
                ddd = int(rng.choice(ddd_keys))
                cpf_dig = next((reg for reg, ddds in CPF_REGION_DDD_MAP.items() if ddd in ddds), 8)
                geo_km = round(float(rng.uniform(1.0, 35.0)), 1)
                dev_status = "Trusted"
                vpn_flag = False
                gps_spoof = False
                rat_flag = False
                cadence = int(rng.integers(78, 99))
                os_sig = str(rng.choice(os_list[:2]))
                isp = str(rng.choice(isps[:3]))
                is_fraud = 0
            elif archetype_roll < 0.74:
                valor = round(float(rng.uniform(1800.0, 9500.0)), 2)
                avg30 = round(float(rng.uniform(220.0, 650.0)), 2)
                hour = int(rng.choice([1, 2, 3, 14, 16, 22, 23]))
                tx24 = int(rng.integers(10, 26))
                dest_age = int(rng.integers(1, 5))
                senders = int(rng.integers(9, 24))
                ddd = int(rng.choice(ddd_keys))
                cpf_dig = int((ddd + 3) % 10)
                geo_km = round(float(rng.uniform(120.0, 680.0)), 1)
                dev_status = str(rng.choice(["New_Device", "VPN_Proxy"]))
                vpn_flag = dev_status == "VPN_Proxy"
                gps_spoof = bool(rng.random() < 0.35)
                rat_flag = False
                cadence = int(rng.integers(52, 76))
                os_sig = str(rng.choice(os_list[2:4]))
                isp = str(rng.choice(isps[3:])) if vpn_flag else str(rng.choice(isps[:3]))
                is_fraud = 1
            elif archetype_roll < 0.88:
                valor = round(float(rng.uniform(3500.0, 18500.0)), 2)
                avg30 = round(float(rng.uniform(300.0, 900.0)), 2)
                hour = int(rng.choice([0, 1, 2, 3, 4, 21, 22, 23]))
                tx24 = int(rng.integers(4, 14))
                dest_age = int(rng.integers(2, 12))
                senders = int(rng.integers(4, 11))
                ddd = int(rng.choice(ddd_keys))
                cpf_dig = int((ddd + 5) % 10)
                geo_km = round(float(rng.uniform(420.0, 1850.0)), 1)
                dev_status = str(rng.choice(["Emulator_Root", "New_Device", "VPN_Proxy"]))
                vpn_flag = True
                gps_spoof = True
                rat_flag = False
                cadence = int(rng.integers(40, 68))
                os_sig = os_list[4] if dev_status == "Emulator_Root" else os_list[2]
                isp = str(rng.choice(isps[3:]))
                is_fraud = 1
            else:
                valor = round(float(rng.uniform(2200.0, 12000.0)), 2)
                avg30 = round(float(rng.uniform(350.0, 800.0)), 2)
                hour = int(rng.integers(9, 22))
                tx24 = int(rng.integers(3, 9))
                dest_age = int(rng.integers(1, 6))
                senders = int(rng.integers(5, 14))
                ddd = int(rng.choice(ddd_keys))
                cpf_dig = next((reg for reg, ddds in CPF_REGION_DDD_MAP.items() if ddd in ddds), 8)
                geo_km = round(float(rng.uniform(15.0, 290.0)), 1)
                dev_status = str(rng.choice(["Trusted", "New_Device"]))
                vpn_flag = False
                gps_spoof = False
                rat_flag = True
                cadence = int(rng.integers(18, 44))
                os_sig = str(rng.choice(os_list[:3]))
                isp = str(rng.choice(isps[:3]))
                is_fraud = 1

            fp_hash = hashlib.md5(f"DEV-{i}-{os_sig}-{ddd}".encode()).hexdigest()[:10].upper()
            session_fp = hashlib.sha256(f"SESS-{i}-{valor}-{fp_hash}".encode()).hexdigest()[:14]

            records.append(
                {
                    "txId": f"PIX-2026-{10000 + i}",
                    "accountId": f"ACC-{1000 + (i % 110)}",
                    "originBank": str(rng.choice(banks)),
                    "destBank": str(rng.choice(banks)),
                    "pixKeyType": str(rng.choice(key_types, p=[0.30, 0.10, 0.22, 0.13, 0.25])),
                    "pixKey": f"chave_{100 + (i % 45)}@pix.bcb.gov.br",
                    "valor": valor,
                    "avgValue30d": avg30,
                    "hour": hour,
                    "txCount24h": tx24,
                    "destAccountAgeDays": dest_age,
                    "uniqueSenders24h": senders,
                    "cpf_9th_digit": cpf_dig,
                    "ddd_telefone": ddd,
                    "geoDistanceKm": geo_km,
                    "deviceStatus": dev_status,
                    "device_fingerprint_id": f"DFP-{fp_hash}",
                    "os_browser": os_sig,
                    "ip_address": f"177.{int(rng.integers(10, 250))}.{int(rng.integers(1, 254))}.{int(rng.integers(2, 253))}",
                    "asn_isp": isp,
                    "vpn_proxy_tor": vpn_flag,
                    "gps_spoofing": gps_spoof,
                    "remote_access_rat": rat_flag,
                    "typing_cadence_score": cadence,
                    "network_latency_ms": int(rng.integers(18, 95)),
                    "session_footprint_hash": f"SFP-{session_fp}",
                    "isFraud": is_fraud,
                }
            )

        return pd.DataFrame(records)


# ==============================================================================
# 6. SDK DE DISPOSITIVO, FINGERPRINT & NETWORK FOOTPRINT (REFERÊNCIA B2B)
# ==============================================================================

SYNAPSE_JS_SDK_SNIPPET = """// Synapse Device & Network Footprint SDK v2.4 (Web / React Native / Flutter Bridge)
import { SynapseShieldSDK } from '@synapse-faas/pix-device-sdk';

const synapse = new SynapseShieldSDK({
  apiKey: '{{API_TOKEN}}',
  endpoint: 'https://api.synapsefraud.io/v1/telemetry/collect',
  enableBehavioralBiometrics: true,
  detectRemoteAccessOverlay: true, // Detecta TeamViewer / AnyDesk / Mão Fantasma
});

export async function scorePixTransaction(pixPayload) {
  const telemetry = await synapse.collectFootprint({
    collectCanvasWebGLHash: true,
    checkEmulatorRootJailbreak: true,
    probeWebRTCNetworkLeak: true,
    measureTypingCadenceOnPixKey: true,
  });

  const response = await fetch('https://api.synapsefraud.io/v1/pix/score', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer {{API_TOKEN}}`,
      'Content-Type': 'application/json',
      'X-Synapse-Device-FP': telemetry.deviceFingerprintId,
    },
    body: JSON.stringify({
      transaction: pixPayload,
      device_layer: {
        device_fingerprint_id: telemetry.deviceFingerprintId,
        os_browser: telemetry.osBrowserSignature,
        device_status: telemetry.integrityStatus, // Trusted | New_Device | Emulator_Root | VPN_Proxy
        remote_access_rat: telemetry.hasActiveScreenShareOrOverlay,
        typing_cadence_score: telemetry.typingCadenceScore,
      },
      network_footprint: {
        ip_address: telemetry.publicIp,
        asn_isp: telemetry.asnOrganization,
        vpn_proxy_tor: telemetry.isAnonymousNetwork,
        gps_spoofing: telemetry.isMockLocationEnabled,
        network_latency_ms: telemetry.rttLatencyMs,
        session_footprint_hash: telemetry.sessionFootprintHash,
      }
    }),
  });

  return await response.json(); // { score: 0..99, decision, ai_recommendation, automation_trigger }
}"""

SYNAPSE_PYTHON_API_SNIPPET = """import requests

SYNAPSE_API_TOKEN = "{{API_TOKEN}}"
SYNAPSE_URL = "https://api.synapsefraud.io/v1/pix/score"

payload = {
    "txId": "PIX-2026-99412",
    "accountId": "ACC-7821",
    "valor": 6450.00,
    "avgValue30d": 420.00,
    "hour": 23,
    "txCount24h": 11,
    "destAccountAgeDays": 2,
    "uniqueSenders24h": 14,
    "cpf_9th_digit": 8,
    "ddd_telefone": 85,
    "geoDistanceKm": 1420.5,
    "deviceStatus": "Emulator_Root",
    "device_fingerprint_id": "DFP-992AC10F4",
    "vpn_proxy_tor": True,
    "remote_access_rat": False,
    "typing_cadence_score": 41
}

response = requests.post(
    SYNAPSE_URL,
    json=payload,
    headers={"Authorization": f"Bearer {SYNAPSE_API_TOKEN}"},
    timeout=2
)
print(response.json())"""


# ==============================================================================
# 7. RENDERIZADOR MULTI-BACKEND DE GRÁFICOS (PLOTLY -> ALTAIR -> SVG/NATIVO)
# ==============================================================================


def format_brl(value: float) -> str:
    return f"R$ {value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")


def safe_rerun() -> None:
    if st is None:
        return
    if hasattr(st, "rerun"):
        st.rerun()
    elif hasattr(st, "experimental_rerun"):
        st.experimental_rerun()


def safe_dataframe(df: pd.DataFrame, height: Optional[int] = None) -> None:
    if st is None:
        return
    kwargs: Dict[str, Any] = {"use_container_width": True}
    if height is not None:
        kwargs["height"] = height
    try:
        st.dataframe(df, hide_index=True, **kwargs)
    except TypeError:
        st.dataframe(df, **kwargs)


class ChartRenderer:
    """
    Motor de Visualização Multi-Backend (Strategy/Adapter).
    Evita falhas `AttributeError: 'NoneType' object has no attribute 'Figure'` no
    Streamlit in Snowflake quando o pacote `plotly` não está habilitado no container,
    utilizando automaticamente Altair (nativo do Snowflake) ou SVG/HTML fallback.
    """

    @staticmethod
    def build_svg_donut_html(
        df_grp: pd.DataFrame,
        category_col: str,
        value_col: str,
        count_col: str,
        pct_col: str,
        title: str,
        color_map: Dict[str, str],
    ) -> str:
        """Gera um gráfico de Rosca (Donut) em SVG/HTML puro com legenda completa (%, R$ e Qtd)."""
        total_val = float(df_grp[value_col].sum()) or 1.0
        palette = ["#00E676", "#38BDF8", "#FBBF24", "#F97316", "#EF4444", "#A855F7"]
        circles_svg = []
        legend_rows = []
        cumulative_pct = 0.0

        for idx, row in df_grp.iterrows():
            cat = str(row[category_col])
            val = float(row[value_col])
            cnt = int(row[count_col])
            pct = float(row[pct_col])
            share = (val / total_val) * 100.0
            color = color_map.get(cat, palette[idx % len(palette)])
            dash_array = f"{share:.2f} {100.0 - share:.2f}"
            dash_offset = f"{100.0 - cumulative_pct + 25.0:.2f}"
            cumulative_pct += share

            circles_svg.append(
                f'<circle width="100%" height="100%" cx="21" cy="21" r="15.91549430918954" '
                f'fill="transparent" stroke="{color}" stroke-width="5.2" '
                f'stroke-dasharray="{dash_array}" stroke-dashoffset="{dash_offset}"></circle>'
            )
            legend_rows.append(
                f'<div style="display:flex;justify-content:space-between;align-items:center;'
                f'padding:4px 0;border-bottom:1px solid #1E293B;font-size:0.80rem;">'
                f'<span><span style="display:inline-block;width:10px;height:10px;border-radius:50%;'
                f'background:{color};margin-right:7px;"></span><b>{cat}</b></span>'
                f'<span style="color:#E2E8F0;">{pct:.1f}% • {cnt} tx • {format_brl(val)}</span>'
                f"</div>"
            )

        return (
            f'<div style="background:#0F172A;border:1px solid #1E293B;border-radius:12px;padding:1rem;">'
            f'<div style="font-weight:700;font-size:0.92rem;color:#F8FAFC;margin-bottom:0.6rem;">{title}</div>'
            f'<div style="display:flex;align-items:center;gap:1.2rem;flex-wrap:wrap;">'
            f'<div style="width:155px;height:155px;flex-shrink:0;margin:0 auto;">'
            f'<svg width="100%" height="100%" viewBox="0 0 42 42">'
            f'<circle cx="21" cy="21" r="15.91549430918954" fill="transparent" stroke="#1E293B" stroke-width="5.2"></circle>'
            f'{"".join(circles_svg)}'
            f"</svg></div>"
            f'<div style="flex:1;min-width:210px;">{"".join(legend_rows)}</div>'
            f"</div></div>"
        )

    @classmethod
    def render_donut(
        cls,
        df_grp: pd.DataFrame,
        category_col: str,
        theta_col: str,
        valor_col: str,
        count_col: str,
        pct_col: str,
        title: str,
        color_map: Dict[str, str],
    ) -> None:
        if st is None:
            return

        if HAS_PLOTLY and go is not None:
            fig = go.Figure(
                data=[
                    go.Pie(
                        labels=df_grp[category_col],
                        values=df_grp[theta_col],
                        hole=0.58,
                        text=df_grp["label_rich"],
                        textinfo="text",
                        marker=dict(colors=[color_map.get(str(d), "#38BDF8") for d in df_grp[category_col]]),
                        hovertemplate=(
                            "<b>%{label}</b><br>"
                            "Participação: %{percent}<br>"
                            "Detalhe: %{text}<extra></extra>"
                        ),
                    )
                ]
            )
            fig.update_layout(
                title=title,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#F8FAFC"),
                height=390,
                legend=dict(orientation="h", y=-0.15),
            )
            st.plotly_chart(fig, use_container_width=True)
            return

        if HAS_ALTAIR and alt is not None:
            try:
                domain_cats = list(df_grp[category_col].astype(str))
                range_cols = [color_map.get(c, "#38BDF8") for c in domain_cats]
                chart = (
                    alt.Chart(df_grp, title=title)
                    .mark_arc(innerRadius=62, outerRadius=118, stroke="#06090F", strokeWidth=2)
                    .encode(
                        theta=alt.Theta(field=theta_col, type="quantitative"),
                        color=alt.Color(
                            field=category_col,
                            type="nominal",
                            scale=alt.Scale(domain=domain_cats, range=range_cols),
                            legend=alt.Legend(title="Categoria", orient="bottom"),
                        ),
                        tooltip=[
                            alt.Tooltip(category_col, title="Categoria"),
                            alt.Tooltip(pct_col, title="Percentual (%)", format=".1f"),
                            alt.Tooltip(count_col, title="Quantidade (#)"),
                            alt.Tooltip(valor_col, title="Valor Total (R$)", format=",.2f"),
                        ],
                    )
                    .properties(height=300)
                )
                st.altair_chart(chart, use_container_width=True)
                # Exibe resumo compacto com %, Valor R$ e Quantidade logo abaixo da rosca
                summary_view = pd.DataFrame(
                    {
                        "Categoria": df_grp[category_col],
                        "%": df_grp[pct_col].map(lambda v: f"{float(v):.1f}%"),
                        "Qtd (#)": df_grp[count_col].astype(int),
                        "Valor (R$)": df_grp[valor_col].map(lambda v: format_brl(float(v))),
                    }
                )
                safe_dataframe(summary_view)
                return
            except Exception:
                pass

        # Fallback SVG/HTML universal
        html_donut = cls.build_svg_donut_html(
            df_grp=df_grp,
            category_col=category_col,
            value_col=valor_col,
            count_col=count_col,
            pct_col=pct_col,
            title=title,
            color_map=color_map,
        )
        st.markdown(html_donut, unsafe_allow_html=True)

    @classmethod
    def render_stacked_bar(
        cls,
        df_grp: pd.DataFrame,
        x_col: str,
        y_col: str,
        color_col: str,
        title: str,
        x_title: str,
        y_title: str,
        color_map: Dict[str, str],
        height: int = 400,
    ) -> None:
        if st is None:
            return

        if HAS_PLOTLY and px is not None:
            fig = px.bar(
                df_grp,
                x=x_col,
                y=y_col,
                color=color_col,
                barmode="stack",
                text_auto=True,
                color_discrete_map=color_map,
                labels={x_col: x_title, y_col: y_title, color_col: "Classificação"},
                title=title,
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#F8FAFC"),
                height=height,
                xaxis_tickangle=-18,
                legend=dict(orientation="h", y=-0.28),
            )
            st.plotly_chart(fig, use_container_width=True)
            return

        if HAS_ALTAIR and alt is not None:
            try:
                domain_cats = [c for c in color_map.keys() if c in set(df_grp[color_col].astype(str))]
                if not domain_cats:
                    domain_cats = list(df_grp[color_col].astype(str).unique())
                range_cols = [color_map.get(c, "#38BDF8") for c in domain_cats]
                chart = (
                    alt.Chart(df_grp, title=title)
                    .mark_bar(cornerRadiusTopLeft=3, cornerRadiusTopRight=3)
                    .encode(
                        x=alt.X(f"{x_col}:N", title=x_title, axis=alt.Axis(labelAngle=-20)),
                        y=alt.Y(f"{y_col}:Q", stack="zero", title=y_title),
                        color=alt.Color(
                            f"{color_col}:N",
                            title="Política / Status",
                            scale=alt.Scale(domain=domain_cats, range=range_cols),
                            legend=alt.Legend(orient="bottom"),
                        ),
                        tooltip=[x_col, color_col, alt.Tooltip(y_col, format=",.2f")],
                    )
                    .properties(height=height - 40)
                )
                st.altair_chart(chart, use_container_width=True)
                return
            except Exception:
                pass

        st.markdown(f"**{title}**")
        pivoted = df_grp.pivot(index=x_col, columns=color_col, values=y_col).fillna(0)
        st.bar_chart(pivoted)

    @classmethod
    def render_cluster_scatter(cls, df_scored: pd.DataFrame) -> None:
        if st is None:
            return
        title = "Formação de Clusters: Velocidade 24h vs. Valor (R$) vs. Fan-in de Recebedores"

        if HAS_PLOTLY and px is not None:
            fig = px.scatter(
                df_scored,
                x="txCount24h",
                y="valor",
                size="uniqueSenders24h",
                color="clusterName",
                hover_name="txId",
                hover_data=["accountId", "pixKey", "riskScore", "decision", "fraudTypology", "uf"],
                color_discrete_sequence=["#00E676", "#EF4444", "#F97316", "#38BDF8"],
                labels={
                    "txCount24h": "Velocidade Transacional (Pix em 24h)",
                    "valor": "Valor da Transação (R$)",
                    "clusterName": "Cluster Identificado",
                    "uniqueSenders24h": "Pagadores Distintos (Fan-in)",
                },
                title=title,
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#F8FAFC"),
                height=430,
                legend=dict(orientation="h", y=-0.25),
            )
            st.plotly_chart(fig, use_container_width=True)
            return

        if HAS_ALTAIR and alt is not None:
            try:
                chart = (
                    alt.Chart(df_scored, title=title)
                    .mark_circle(opacity=0.82, stroke="#06090F", strokeWidth=1)
                    .encode(
                        x=alt.X("txCount24h:Q", title="Velocidade Transacional (Pix em 24h)"),
                        y=alt.Y("valor:Q", title="Valor da Transação (R$)"),
                        size=alt.Size("uniqueSenders24h:Q", title="Fan-in Recebedor", scale=alt.Scale(range=[40, 520])),
                        color=alt.Color(
                            "clusterName:N",
                            title="Cluster",
                            scale=alt.Scale(range=["#00E676", "#EF4444", "#F97316", "#38BDF8"]),
                            legend=alt.Legend(orient="bottom"),
                        ),
                        tooltip=[
                            "txId",
                            "accountId",
                            "pixKey",
                            "valor",
                            "txCount24h",
                            "uniqueSenders24h",
                            "riskScore",
                            "decision",
                            "clusterName",
                        ],
                    )
                    .properties(height=390)
                    .interactive()
                )
                st.altair_chart(chart, use_container_width=True)
                return
            except Exception:
                pass

        st.markdown(f"**{title}**")
        safe_dataframe(df_scored[["txId", "clusterName", "txCount24h", "valor", "uniqueSenders24h", "riskScore"]].head(20))

    @classmethod
    def render_geo_map(cls, df_scored: pd.DataFrame) -> None:
        if st is None:
            return
        title = "Mapa Geográfico de Risco Pix (Concentração por DDD/UF e Decisão)"

        if HAS_PLOTLY and px is not None:
            fig_map = px.scatter_geo(
                df_scored,
                lat="lat",
                lon="lon",
                color="decision",
                size="valor",
                hover_name="city",
                hover_data=["txId", "uf", "ddd_telefone", "cpf_9th_digit", "geoDistanceKm", "riskScore"],
                color_discrete_map=DECISION_COLOR_MAP,
                scope="south america",
                title=title,
            )
            fig_map.update_geos(
                center=dict(lat=-14.2350, lon=-51.9253),
                projection_scale=3.2,
                bgcolor="rgba(6,9,15,1)",
                landcolor="#0F172A",
                subunitcolor="#1E293B",
                countrycolor="#334155",
                showcountries=True,
            )
            fig_map.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#F8FAFC"),
                height=440,
                margin=dict(l=0, r=0, t=40, b=0),
            )
            st.plotly_chart(fig_map, use_container_width=True)
            return

        st.markdown(f"##### 🗺️ {title}")
        try:
            st.map(df_scored[["lat", "lon"]])
        except Exception:
            if HAS_ALTAIR and alt is not None:
                chart = (
                    alt.Chart(df_scored)
                    .mark_circle(opacity=0.85)
                    .encode(
                        x=alt.X("lon:Q", title="Longitude", scale=alt.Scale(zero=False)),
                        y=alt.Y("lat:Q", title="Latitude", scale=alt.Scale(zero=False)),
                        size=alt.Size("valor:Q", title="Valor (R$)"),
                        color=alt.Color("decision:N", title="Decisão"),
                        tooltip=["city", "uf", "ddd_telefone", "valor", "riskScore", "decision"],
                    )
                    .properties(height=380)
                )
                st.altair_chart(chart, use_container_width=True)


# ==============================================================================
# 8. CAMADA DE APRESENTAÇÃO STREAMLIT (DARK MODE + GRADIENTE BRASIL)
# ==============================================================================


def inject_synapse_theme() -> None:
    st.markdown(
        """
        <style>
        .stApp {
            background-color: #06090F;
            color: #F8FAFC;
        }
        [data-testid="stSidebar"] {
            background-color: #0B111E;
            border-right: 1px solid #1E293B;
        }
        .synapse-hero {
            background: linear-gradient(90deg, #004E92 0%, #00A859 55%, #00E676 100%);
            padding: 1.5rem 2rem;
            border-radius: 14px;
            color: #FFFFFF;
            margin-bottom: 1.4rem;
            box-shadow: 0 10px 28px -6px rgba(0, 168, 89, 0.42);
        }
        .synapse-hero h1 {
            margin: 0;
            font-size: 1.85rem;
            font-weight: 800;
            color: #FFFFFF !important;
            letter-spacing: -0.02em;
        }
        .synapse-hero p {
            margin: 0.35rem 0 0 0;
            font-size: 0.96rem;
            opacity: 0.94;
            color: #F0FDF4;
        }
        .kpi-card {
            background: linear-gradient(145deg, #0F172A 0%, #131F36 100%);
            border: 1px solid #1E293B;
            border-left: 4px solid #00E676;
            padding: 1.05rem 1.15rem;
            border-radius: 12px;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.35);
            margin-bottom: 0.8rem;
        }
        .kpi-card.warn {
            border-left-color: #F59E0B;
        }
        .kpi-card.danger {
            border-left-color: #EF4444;
        }
        .kpi-card.info {
            border-left-color: #38BDF8;
        }
        .kpi-title {
            font-size: 0.76rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #94A3B8;
            font-weight: 700;
        }
        .kpi-value {
            font-size: 1.55rem;
            font-weight: 800;
            color: #F8FAFC;
            margin-top: 0.25rem;
        }
        .kpi-sub {
            font-size: 0.78rem;
            color: #10B981;
            margin-top: 0.2rem;
        }
        .badge-role {
            display: inline-block;
            padding: 0.25rem 0.7rem;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 700;
            background: rgba(0, 230, 118, 0.15);
            color: #00E676;
            border: 1px solid rgba(0, 230, 118, 0.4);
        }
        .token-box {
            background-color: #091326;
            border: 1px solid #00A859;
            border-radius: 10px;
            padding: 0.9rem 1.1rem;
            font-family: monospace;
            color: #00E676;
            font-size: 0.9rem;
            margin: 0.5rem 0;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def init_session_state() -> None:
    if "auth_user" not in st.session_state:
        st.session_state.auth_user = None
    if "risk_weights" not in st.session_state:
        st.session_state.risk_weights = PixRiskWeights()
    if "b2b_tenant" not in st.session_state:
        st.session_state.b2b_tenant = OnboardingTenantService.provision_tenant_and_tokens(
            cnpj="18236120000158",
            company_name="Synapse Pay Instituição de Pagamento S.A.",
            ispb_code="18236120",
            segment="Instituição de Pagamento / PSP Pix",
            monthly_pix_volume=2_500_000,
            contact_email="fraude-pix@synapsepay.com.br",
            webhook_url="https://api.synapsepay.com.br/v1/webhooks/pix-decision",
        )
    if "raw_pix_df" not in st.session_state:
        df_init, label_init = FeatureStoreRepository.load_from_snowflake_or_default(360)
        st.session_state.raw_pix_df = df_init
        st.session_state.data_source_label = label_init
    if "automation_audit_log" not in st.session_state:
        st.session_state.automation_audit_log = []


def render_login_screen() -> None:
    inject_synapse_theme()
    st.markdown(
        """
        <div class="synapse-hero">
            <h1>🛡️ SYNAPSE PIX SHIELD — Antifraude-as-a-Service (FaaS)</h1>
            <p>Autenticação Corporativa RBAC • Prevenção a Golpes Pix com IA, Feature Store Snowflake & Device SDK</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_left, col_center, col_right = st.columns([1, 1.35, 1])
    with col_center:
        st.markdown("### 🔐 Acesso Seguro à Plataforma")
        st.caption(
            "O perfil de acesso (`Administrador`, `Analista` ou `Auditor`) é resolvido automaticamente "
            "pelo servidor a partir das suas credenciais autenticadas (RBAC)."
        )

        with st.form("synapse_rbac_login_form", clear_on_submit=False):
            identifier = st.text_input(
                "E-mail Corporativo ou Usuário",
                value="admin@synapse.io",
                placeholder="ex: admin@synapse.io",
            )
            password = st.text_input(
                "Senha",
                type="password",
                value="Synapse@Admin2026",
            )
            submitted = st.form_submit_button("Entrar no Cockpit Synapse", use_container_width=True)

            if submitted:
                auth_user = AuthenticationService.authenticate(identifier, password)
                if auth_user is not None:
                    st.session_state.auth_user = auth_user
                    safe_rerun()
                else:
                    st.error("❌ Credenciais inválidas. Verifique seu usuário/e-mail e senha.")

        with st.expander("🔑 Credenciais de Demonstração (Homologação MVP / RBAC)", expanded=True):
            st.markdown(
                """
                | Perfil RBAC | E-mail / Login | Senha | Permissões na Plataforma |
                | :--- | :--- | :--- | :--- |
                | **Administrador** | `admin@synapse.io` | `Synapse@Admin2026` | Acesso total, Calibragem de Pesos, Onboarding B2B & Emissão de API Token |
                | **Analista** | `analista@synapse.io` | `Synapse@Analista2026` | Cockpit, Upload CSV, Análise Individual e Disparo de Automações (Bloqueio 72h / MED) |
                | **Auditor** | `auditor@synapse.io` | `Synapse@Auditor2026` | Somente leitura do Cockpit Executivo e Exportação de Relatórios BACEN/MED |
                """
            )


def render_executive_cockpit(df_scored: pd.DataFrame) -> None:
    st.markdown("### 📊 Cockpit Executivo — Storytelling de Risco Pix em Tempo Real")
    st.caption(
        "Visão consolidada para Diretoria, Risco e Operações: impacto financeiro evitado, formação de clusters, "
        "políticas de decisão e distribuição por tipologia de golpe Pix."
    )

    total_tpv = float(df_scored["valor"].sum())
    total_tx = int(len(df_scored))

    blocked_mask = df_scored["decision"].isin(["BLOQUEIO CAUTELAR (72h)", "REPROVADO / ABRIR MED"])
    stepup_mask = df_scored["decision"].isin(["MFA / STEP-UP", "REVISÃO MANUAL"])
    approved_mask = df_scored["decision"] == "APROVADO"

    prevented_brl = float(df_scored.loc[blocked_mask, "valor"].sum())
    blocked_count = int(blocked_mask.sum())
    cautelar_count = int((df_scored["decision"] == "BLOQUEIO CAUTELAR (72h)").sum())
    med_count = int((df_scored["decision"] == "REPROVADO / ABRIR MED").sum())
    avg_score = float(df_scored["riskScore"].mean())
    avg_latency = float(df_scored["engineLatencyMs"].mean())
    approval_rate = (float(approved_mask.sum()) / max(total_tx, 1)) * 100.0
    prevented_pct_tpv = (prevented_brl / max(total_tpv, 1.0)) * 100.0

    # 1. BIG NUMBERS (6 Cards Executivos)
    c1, c2, c3, c4, c5, c6 = st.columns(6)
    with c1:
        st.markdown(
            f"""<div class="kpi-card">
                <div class="kpi-title">TPV Pix Analisado</div>
                <div class="kpi-value">{format_brl(total_tpv)}</div>
                <div class="kpi-sub">100% inspecionado via IA</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f"""<div class="kpi-card info">
                <div class="kpi-title">Transações Pix</div>
                <div class="kpi-value">{total_tx:,}</div>
                <div class="kpi-sub">Aprovação direta: {approval_rate:.1f}%</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f"""<div class="kpi-card">
                <div class="kpi-title">Fraudes Evitadas (R$)</div>
                <div class="kpi-value">{format_brl(prevented_brl)}</div>
                <div class="kpi-sub">{prevented_pct_tpv:.1f}% do TPV protegido</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f"""<div class="kpi-card danger">
                <div class="kpi-title">Bloqueio 72h & MED</div>
                <div class="kpi-value">{blocked_count} ops</div>
                <div class="kpi-sub">{cautelar_count} Cautelares | {med_count} MED</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with c5:
        st.markdown(
            f"""<div class="kpi-card warn">
                <div class="kpi-title">Score Médio Carteira</div>
                <div class="kpi-value">{avg_score:.1f} / 99</div>
                <div class="kpi-sub">{int(stepup_mask.sum())} em Step-Up / Revisão</div>
            </div>""",
            unsafe_allow_html=True,
        )
    with c6:
        st.markdown(
            f"""<div class="kpi-card info">
                <div class="kpi-title">SLA Motor FaaS</div>
                <div class="kpi-value">{avg_latency:.0f} ms</div>
                <div class="kpi-sub">P99 &lt; 85ms (SPI BACEN)</div>
            </div>""",
            unsafe_allow_html=True,
        )

    # 2. GRÁFICOS DE ROSCA (DONUT) COM PERCENTUAL (%), VALOR (R$) E QUANTIDADE (#)
    st.markdown("#### 🍩 Visão Proporcional: Percentual (%), Valor Financeiro (R$) e Quantidade (#)")
    donut_col1, donut_col2 = st.columns(2)

    with donut_col1:
        grp_dec = (
            df_scored.groupby("decision", as_index=False)
            .agg(quantidade=("txId", "count"), valor_total=("valor", "sum"))
        )
        grp_dec["pct_qtd"] = (grp_dec["quantidade"] / max(total_tx, 1)) * 100.0
        grp_dec["label_rich"] = grp_dec.apply(
            lambda r: f"{r['decision']}<br>{r['pct_qtd']:.1f}% | {int(r['quantidade'])} tx | {format_brl(float(r['valor_total']))}",
            axis=1,
        )
        ChartRenderer.render_donut(
            df_grp=grp_dec,
            category_col="decision",
            theta_col="valor_total",
            valor_col="valor_total",
            count_col="quantidade",
            pct_col="pct_qtd",
            title="Rosca por Política de Decisão (%, Valor R$ e Qtd)",
            color_map=DECISION_COLOR_MAP,
        )

    with donut_col2:
        grp_typ = (
            df_scored.groupby("fraudTypology", as_index=False)
            .agg(quantidade=("txId", "count"), valor_total=("valor", "sum"))
        )
        grp_typ["pct_val"] = (grp_typ["valor_total"] / max(total_tpv, 1.0)) * 100.0
        grp_typ["label_rich"] = grp_typ.apply(
            lambda r: f"{r['fraudTypology']}<br>{r['pct_val']:.1f}% | {int(r['quantidade'])} tx | {format_brl(float(r['valor_total']))}",
            axis=1,
        )
        ChartRenderer.render_donut(
            df_grp=grp_typ,
            category_col="fraudTypology",
            theta_col="quantidade",
            valor_col="valor_total",
            count_col="quantidade",
            pct_col="pct_val",
            title="Rosca por Tipologia de Golpe Pix (%, Qtd e Valor R$)",
            color_map=TYPOLOGY_COLOR_MAP,
        )

    # 3. GRÁFICOS DE BARRAS EMPILHADAS (VALOR R$ E QUANTIDADE)
    st.markdown("#### 📊 Gráficos de Barras Empilhadas: Exposição Financeira (R$) e Volume de Operações (#)")
    bar_col1, bar_col2 = st.columns(2)

    with bar_col1:
        grp_stack_val = (
            df_scored.groupby(["fraudTypology", "decision"], as_index=False)
            .agg(valor_brl=("valor", "sum"), qtd=("txId", "count"))
        )
        ChartRenderer.render_stacked_bar(
            df_grp=grp_stack_val,
            x_col="fraudTypology",
            y_col="valor_brl",
            color_col="decision",
            title="Barras Empilhadas — Valor (R$) por Tipologia x Decisão",
            x_title="Tipologia de Golpe Pix",
            y_title="Valor Financeiro (R$)",
            color_map=DECISION_COLOR_MAP,
        )

    with bar_col2:
        grp_stack_qtd = (
            df_scored.groupby(["destBank", "decision"], as_index=False)
            .agg(quantidade=("txId", "count"), valor_brl=("valor", "sum"))
        )
        ChartRenderer.render_stacked_bar(
            df_grp=grp_stack_qtd,
            x_col="destBank",
            y_col="quantidade",
            color_col="decision",
            title="Barras Empilhadas — Quantidade (#) por Instituição Destino x Decisão",
            x_title="Instituição Recebedora (Destino)",
            y_title="Quantidade de Transações (#)",
            color_map=DECISION_COLOR_MAP,
        )


def render_clusters_and_geography(df_scored: pd.DataFrame) -> None:
    st.markdown("### 🕸️ Formação de Clusters de Fraude Pix & Inteligência Geográfica (CPF x DDD)")
    st.caption(
        "Detecção de redes de Contas Laranja (Mule Rings), dispersão multi-dimensional de velocidade x valor "
        "e auditoria espacial de divergência entre Região Fiscal do CPF (9º dígito) e DDD de origem."
    )

    cl_col1, cl_col2 = st.columns([1.35, 1])
    with cl_col1:
        ChartRenderer.render_cluster_scatter(df_scored)

    with cl_col2:
        cluster_summary = (
            df_scored.groupby("clusterName", as_index=False)
            .agg(
                Transacoes=("txId", "count"),
                Volume_BRL=("valor", "sum"),
                Score_Medio=("riskScore", "mean"),
                FanIn_Medio=("uniqueSenders24h", "mean"),
            )
            .sort_values("Score_Medio", ascending=False)
        )
        cluster_summary["Score_Medio"] = cluster_summary["Score_Medio"].round(1)
        cluster_summary["FanIn_Medio"] = cluster_summary["FanIn_Medio"].round(1)
        st.markdown("##### 📌 Resumo da Formação de Clusters")
        safe_dataframe(cluster_summary)

        mule_suspects = (
            df_scored[df_scored["riskScore"] >= 60]
            .groupby(["pixKey", "destBank", "uf"], as_index=False)
            .agg(
                Qtd_Recebimentos=("txId", "count"),
                Pagadores_Unicos=("uniqueSenders24h", "max"),
                Valor_Total_BRL=("valor", "sum"),
                Score_Max=("riskScore", "max"),
            )
            .sort_values(["Pagadores_Unicos", "Valor_Total_BRL"], ascending=False)
            .head(6)
        )
        st.markdown("##### 🚨 Top Chaves Pix Recebedoras Suspeitas (Anel de Contas Laranja)")
        safe_dataframe(mule_suspects)

    st.markdown("---")
    geo_col1, geo_col2 = st.columns([1.25, 1])

    with geo_col1:
        ChartRenderer.render_geo_map(df_scored)

    with geo_col2:
        mismatch_count = int((~df_scored["cpf_ddd_consistente"]).sum())
        long_dist_count = int((df_scored["geoDistanceKm"] >= 350).sum())
        st.metric(
            "Divergências 9º Dígito CPF vs. DDD (Região Fiscal BACEN)",
            f"{mismatch_count} transações",
            delta=f"{(mismatch_count / max(len(df_scored), 1)) * 100:.1f}% da base",
            delta_color="inverse",
        )
        st.metric(
            "Anomalias de Perímetro Geográfico (> 350 km)",
            f"{long_dist_count} transações",
            delta=f"Distância máx: {df_scored['geoDistanceKm'].max():.0f} km",
            delta_color="inverse",
        )

        uf_grp = (
            df_scored.groupby(["uf", "cpf_ddd_consistente"], as_index=False)
            .agg(valor_brl=("valor", "sum"), qtd=("txId", "count"))
        )
        uf_grp["Status_CPF_DDD"] = np.where(
            uf_grp["cpf_ddd_consistente"], "Consistente (Mesma Região Fiscal)", "Divergente (Alerta Fraude)"
        )
        ChartRenderer.render_stacked_bar(
            df_grp=uf_grp,
            x_col="uf",
            y_col="valor_brl",
            color_col="Status_CPF_DDD",
            title="Exposição Financeira (R$) por UF x Validação Região Fiscal CPF/DDD",
            x_title="UF",
            y_title="Valor Financeiro (R$)",
            color_map={
                "Consistente (Mesma Região Fiscal)": "#00A859",
                "Divergente (Alerta Fraude)": "#EF4444",
            },
            height=300,
        )


def render_device_fingerprint_and_sdk(df_scored: pd.DataFrame, tenant: B2BTenantConfig) -> None:
    st.markdown("### 📱 Camada do Dispositivo, Device Fingerprint, Network Footprint & SDK")
    st.caption(
        "Inspeção profunda dos sinais de hardware, sistema operacional, integridade do aparelho (Root/Emulador/RAT), "
        "pegada de rede (IP, ASN/ISP, VPN/Proxy/Tor, GPS Spoofing) e código do SDK para coleta client-side."
    )

    emul_cnt = int((df_scored["deviceStatus"] == "Emulator_Root").sum())
    vpn_cnt = int(df_scored["vpn_proxy_tor"].astype(bool).sum())
    rat_cnt = int(df_scored["remote_access_rat"].astype(bool).sum())
    gps_cnt = int(df_scored["gps_spoofing"].astype(bool).sum())

    d1, d2, d3, d4 = st.columns(4)
    d1.metric("Emuladores / Root / Jailbreak", f"{emul_cnt} acessos", "Camada de Hardware")
    d2.metric("Rede Anônima (VPN / Proxy / Tor)", f"{vpn_cnt} acessos", "Network Footprint")
    d3.metric("Acesso Remoto / RAT (Mão Fantasma)", f"{rat_cnt} sessões", "Overlay / ScreenShare")
    d4.metric("GPS Spoofing (Mock Location)", f"{gps_cnt} alertas", "Geolocalização Forjada")

    col_fp1, col_fp2 = st.columns(2)
    with col_fp1:
        grp_dev = (
            df_scored.groupby(["deviceStatus", "decision"], as_index=False)
            .agg(qtd=("txId", "count"), valor_brl=("valor", "sum"))
        )
        ChartRenderer.render_stacked_bar(
            df_grp=grp_dev,
            x_col="deviceStatus",
            y_col="valor_brl",
            color_col="decision",
            title="Camada do Dispositivo (Integrity Status) x Valor (R$)",
            x_title="Status do Dispositivo",
            y_title="Valor Financeiro (R$)",
            color_map=DECISION_COLOR_MAP,
            height=360,
        )

    with col_fp2:
        grp_asn = (
            df_scored.groupby(["asn_isp", "decision"], as_index=False)
            .agg(qtd=("txId", "count"), score_medio=("riskScore", "mean"))
        )
        ChartRenderer.render_stacked_bar(
            df_grp=grp_asn,
            x_col="asn_isp",
            y_col="qtd",
            color_col="decision",
            title="Validação de Rede (ASN / Provedor ISP) x Decisão",
            x_title="ASN / Provedor de Rede",
            y_title="Quantidade de Transações (#)",
            color_map=DECISION_COLOR_MAP,
            height=360,
        )

    st.markdown("#### 🔍 Telemetria Detalhada de Quem Acessou (Device Fingerprint & Network Footprint)")
    telemetry_cols = [
        "txId",
        "accountId",
        "device_fingerprint_id",
        "deviceStatus",
        "os_browser",
        "ip_address",
        "asn_isp",
        "vpn_proxy_tor",
        "gps_spoofing",
        "remote_access_rat",
        "typing_cadence_score",
        "network_latency_ms",
        "riskScore",
        "decision",
    ]
    available_cols = [c for c in telemetry_cols if c in df_scored.columns]
    safe_dataframe(df_scored.sort_values("riskScore", ascending=False)[available_cols].head(25))

    with st.expander("💻 Código do Synapse Device & Network SDK (Coleta Client-Side Web/Mobile)", expanded=True):
        st.markdown(
            "Integre este SDK no aplicativo bancário ou checkout Pix para capturar automaticamente "
            "`device_fingerprint_id`, assinatura de SO/Hardware, detecção de Emulador/Root/RAT, "
            "IP/ASN, VPN/Proxy e cadência de digitação:"
        )
        st.code(
            SYNAPSE_JS_SDK_SNIPPET.replace("{{API_TOKEN}}", tenant.api_token_live),
            language="javascript",
        )


def render_b2b_onboarding_page(user: AuthenticatedUser) -> None:
    st.markdown("### 🏢 Onboarding Empresarial B2B — Antifraude-as-a-Service (FaaS)")
    st.caption(
        "Jornada de ativação para Bancos Digitais, Instituições de Pagamento (IP), Fintechs e PSPs: "
        "configure sua Política de Decisão Pix e habilite o Token para consumo via API em segundos."
    )

    current_tenant: B2BTenantConfig = st.session_state.b2b_tenant
    can_edit = user.has_permission("manage_onboarding")

    if not can_edit:
        st.warning(
            f"🔒 Seu perfil atual (**{user.role}**) possui acesso somente leitura às credenciais de Onboarding. "
            "Apenas o perfil **Administrador** pode regenerar tokens de produção."
        )

    with st.form("b2b_onboarding_form"):
        st.markdown("#### Passo 1 — Identificação da Instituição Participante")
        col1, col2, col3 = st.columns(3)
        with col1:
            company_name = st.text_input("Razão Social / Nome da Empresa", value=current_tenant.company_name)
            cnpj = st.text_input("CNPJ (14 dígitos)", value=current_tenant.cnpj)
        with col2:
            ispb_code = st.text_input("ISPB / Código COMPE no SPI", value=current_tenant.ispb_code)
            segment = st.selectbox(
                "Segmento B2B",
                [
                    "Instituição de Pagamento / PSP Pix",
                    "Banco Digital / BaaS",
                    "Fintech de Crédito / SCD",
                    "E-commerce / Subadquirente",
                    "Cooperativa de Crédito",
                ],
                index=0,
            )
        with col3:
            monthly_vol = st.number_input(
                "Volume Mensal Estimado de Pix (#)",
                min_value=1_000,
                max_value=500_000_000,
                value=int(current_tenant.monthly_pix_volume),
                step=50_000,
            )
            contact_email = st.text_input("E-mail da Mesa Antifraude / DICT", value=current_tenant.contact_email)

        st.markdown("#### Passo 2 — Política de Decisão (Score 0–99) & Gatilhos de Automação")
        p1, p2, p3, p4 = st.columns(4)
        with p1:
            t_mfa = st.slider("Limiar MFA / Step-Up Facial", 15, 50, int(current_tenant.threshold_mfa))
        with p2:
            t_rev = st.slider("Limiar Revisão Manual", 51, 70, int(current_tenant.threshold_review))
        with p3:
            t_blk = st.slider("Limiar Bloqueio Cautelar 72h", 71, 85, int(current_tenant.threshold_block_72h))
        with p4:
            t_med = st.slider("Limiar Reprovação + Abrir MED", 86, 98, int(current_tenant.threshold_med))

        a1, a2, a3 = st.columns(3)
        with a1:
            auto_mfa = st.checkbox("Acionar SDK de Biometria Facial (Step-Up)", value=current_tenant.auto_mfa_stepup)
        with a2:
            auto_blk = st.checkbox("Aplicar Bloqueio Cautelar 72h Automático (Res. BCB 147)", value=current_tenant.auto_block_72h)
        with a3:
            auto_med = st.checkbox("Protocolar Abertura de MED Automaticamente", value=current_tenant.auto_open_med)

        webhook_url = st.text_input(
            "Webhook URL de Callback para Decisões Síncronas/Assíncronas",
            value=current_tenant.webhook_url,
        )

        submit_onboarding = st.form_submit_button(
            "🚀 Concluir Onboarding & Habilitar Token de API FaaS",
            use_container_width=True,
            disabled=not can_edit,
        )

        if submit_onboarding and can_edit:
            try:
                new_tenant = OnboardingTenantService.provision_tenant_and_tokens(
                    cnpj=cnpj,
                    company_name=company_name,
                    ispb_code=ispb_code,
                    segment=segment,
                    monthly_pix_volume=int(monthly_vol),
                    contact_email=contact_email,
                    webhook_url=webhook_url,
                    threshold_mfa=t_mfa,
                    threshold_review=t_rev,
                    threshold_block_72h=t_blk,
                    threshold_med=t_med,
                    auto_block_72h=auto_blk,
                    auto_open_med=auto_med,
                    auto_mfa_stepup=auto_mfa,
                )
                st.session_state.b2b_tenant = new_tenant
                current_tenant = new_tenant
                st.success(
                    f"✅ Onboarding concluído para **{new_tenant.company_name}** (`{new_tenant.tenant_id}`)! "
                    "Tokens de Produção e Sandbox habilitados com sucesso."
                )
            except ValueError as err:
                st.error(f"⚠️ Erro na validação do Onboarding: {err}")

    st.markdown("#### Passo 3 — Credenciais de API Habilitadas (`POST /v1/pix/score`)")
    tk_col1, tk_col2 = st.columns(2)
    with tk_col1:
        st.markdown("**🟢 API Token — Produção (Live SPI):**")
        st.markdown(f'<div class="token-box">{current_tenant.api_token_live}</div>', unsafe_allow_html=True)
        st.caption(f"Tenant ID: `{current_tenant.tenant_id}` • Fingerprint SHA-256: `{current_tenant.token_fingerprint}`")
    with tk_col2:
        st.markdown("**🟡 API Token — Homologação (Sandbox Shadow Mode):**")
        st.markdown(f'<div class="token-box">{current_tenant.api_token_sandbox}</div>', unsafe_allow_html=True)
        st.caption(f"Webhook Ativo: `{current_tenant.webhook_url}` • Status: `{current_tenant.status}`")

    with st.expander("📡 Exemplo de Consumo da API via Python / Microsserviço Core Bancário", expanded=False):
        st.code(
            SYNAPSE_PYTHON_API_SNIPPET.replace("{{API_TOKEN}}", current_tenant.api_token_live),
            language="python",
        )


def render_csv_upload_and_individual_analysis(
    df_scored: pd.DataFrame,
    user: AuthenticatedUser,
    tenant: B2BTenantConfig,
) -> None:
    st.markdown("### 🧠 Upload de Base CSV Pix, Motor de Score (0–99) & Análise Individual com IA")
    st.caption(
        "Envie um arquivo CSV com transações Pix para processar o lote completo, gerar scores, políticas de decisão "
        "e recomendações de IA, ou inspecione individualmente qualquer transação com automações em 1 clique."
    )

    up_col1, up_col2 = st.columns([1.4, 1])
    with up_col1:
        uploaded_csv = st.file_uploader(
            "📂 Faça upload da base de dados Pix (.csv)",
            type=["csv"],
            help="Aceita colunas como txId, accountId, valor, avgValue30d, hour, txCount24h, destAccountAgeDays, cpf_9th_digit, ddd_telefone, deviceStatus, geoDistanceKm.",
        )
        if uploaded_csv is not None:
            try:
                df_uploaded = pd.read_csv(uploaded_csv)
                st.session_state.raw_pix_df = df_uploaded
                st.session_state.data_source_label = f"Upload CSV: {uploaded_csv.name} ({len(df_uploaded)} registros)"
                st.success(f"✅ Base `{uploaded_csv.name}` carregada e processada pelo Motor de IA Pix ({len(df_uploaded)} transações)!")
                df_scored = PixScoringEngine.score_dataframe(
                    df_uploaded,
                    weights=st.session_state.risk_weights,
                    tenant_policy=tenant,
                )
            except Exception as exc:
                st.error(f"Erro ao processar CSV: {exc}")

    with up_col2:
        st.markdown("##### ⬇️ Template CSV & Exportação do Lote Processado")
        template_df = FeatureStoreRepository.generate_pix_dataset(25, seed=99)
        st.download_button(
            "📥 Baixar CSV de Exemplo (Template Pix)",
            data=template_df.to_csv(index=False).encode("utf-8"),
            file_name="template_base_pix_synapse.csv",
            mime="text/csv",
            use_container_width=True,
        )
        st.download_button(
            "📤 Exportar Base Processada c/ Score e Recomendações (.csv)",
            data=df_scored.to_csv(index=False).encode("utf-8"),
            file_name="synapse_pix_scored_output.csv",
            mime="text/csv",
            use_container_width=True,
        )

    st.markdown("#### 📋 Lote Pix Processado — Score (0–99), Política de Decisão e Recomendação IA")
    display_cols = [
        "txId",
        "accountId",
        "valor",
        "originBank",
        "destBank",
        "pixKey",
        "riskScore",
        "decision",
        "fraudTypology",
        "clusterName",
        "aiRecommendation",
        "reasons",
    ]
    safe_dataframe(df_scored.sort_values("riskScore", ascending=False)[display_cols], height=320)

    st.markdown("---")
    st.markdown("#### 🔎 Análise Individual de Transação / Chave Pix & Automações Antifraude")

    sorted_df = df_scored.sort_values("riskScore", ascending=False).reset_index(drop=True)
    options_labels = [
        f"{r['txId']} | Score: {r['riskScore']}/99 | {r['decision']} | {format_brl(float(r['valor']))} | {r['fraudTypology']}"
        for _, r in sorted_df.iterrows()
    ]
    selected_idx = st.selectbox(
        "Selecione uma transação Pix para Dossiê Individual e Automação:",
        range(len(options_labels)),
        format_func=lambda i: options_labels[i],
    )
    tx = sorted_df.iloc[int(selected_idx)]

    ind_col1, ind_col2 = st.columns([1.25, 1])
    with ind_col1:
        st.markdown(
            f"""
            <div class="kpi-card {'danger' if tx['riskScore'] >= 75 else ('warn' if tx['riskScore'] >= 35 else '')}">
                <div class="kpi-title">Dossiê Individual • {tx['txId']} ({tx['originBank']} → {tx['destBank']})</div>
                <div class="kpi-value">Score IA: {tx['riskScore']} / 99 — {tx['decision']}</div>
                <div class="kpi-sub">Tipologia: <b>{tx['fraudTypology']}</b> • Cluster: <b>{tx['clusterName']}</b></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.markdown(f"**🧠 Parecer Explicativo da IA:**\n> {tx['aiRecommendation']}")
        st.markdown(f"**📌 Fatores de Risco Detectados:** `{tx['reasons']}`")
        st.markdown(f"**⚡ Gatilho de Automação Vinculado:** `{tx['automationTrigger']}`")

        st.markdown("##### 🤖 Executar Automação no Processo Antifraude (1-Click Action)")
        can_act = user.has_permission("execute_automations")
        b1, b2, b3, b4 = st.columns(4)
        action_taken = None
        if b1.button("📲 Exigir MFA Facial", use_container_width=True, disabled=not can_act):
            action_taken = f"MFA Facial Liveness 3D disparado via SDK para conta {tx['accountId']} ({tx['txId']})."
        if b2.button("⏳ Bloqueio 72h (BCB)", use_container_width=True, disabled=not can_act):
            action_taken = f"Bloqueio Cautelar de 72h (Res. BCB 147) aplicado sobre {format_brl(float(tx['valor']))} na transação {tx['txId']}."
        if b3.button("🚨 Abrir MED BACEN", use_container_width=True, disabled=not can_act):
            action_taken = f"Protocolo MED aberto no DICT/BACEN contra a chave {tx['pixKey']} ({tx['destBank']}) — {tx['txId']}."
        if b4.button("🔗 Disparar Webhook", use_container_width=True, disabled=not can_act):
            action_taken = f"Webhook JSON enviado para {tenant.webhook_url} com decisão {tx['decision']} ({tx['txId']})."

        if action_taken:
            st.session_state.automation_audit_log.insert(
                0,
                {
                    "timestamp": dt.datetime.now().strftime("%H:%M:%S"),
                    "operator": user.email,
                    "role": user.role,
                    "txId": str(tx["txId"]),
                    "action": action_taken,
                },
            )
            st.success(f"✅ Automação executada: {action_taken}")

    with ind_col2:
        st.markdown("##### 🧬 Raio-X Técnico: Conta, Geografia, Fingerprint & Rede")
        st.json(
            {
                "transacao": {
                    "txId": str(tx["txId"]),
                    "accountId": str(tx["accountId"]),
                    "valor_brl": float(tx["valor"]),
                    "media_30d_brl": float(tx["avgValue30d"]),
                    "horario_h": int(tx["hour"]),
                    "velocidade_24h": int(tx["txCount24h"]),
                },
                "recebedor_pix": {
                    "banco_destino": str(tx["destBank"]),
                    "chave_pix": str(tx["pixKey"]),
                    "idade_chave_dias": int(tx["destAccountAgeDays"]),
                    "pagadores_distintos_24h": int(tx["uniqueSenders24h"]),
                },
                "validacao_geografica": {
                    "uf_cidade": f"{tx['uf']} - {tx['city']}",
                    "ddd_acesso": int(tx["ddd_telefone"]),
                    "cpf_9o_digito_fiscal": int(tx["cpf_9th_digit"]),
                    "cpf_ddd_consistente": bool(tx["cpf_ddd_consistente"]),
                    "distancia_perimetro_km": float(tx["geoDistanceKm"]),
                },
                "camada_dispositivo_e_rede_sdk": {
                    "device_fingerprint_id": str(tx["device_fingerprint_id"]),
                    "device_status": str(tx["deviceStatus"]),
                    "os_browser": str(tx["os_browser"]),
                    "ip_address": str(tx["ip_address"]),
                    "asn_isp": str(tx["asn_isp"]),
                    "vpn_proxy_tor": bool(tx["vpn_proxy_tor"]),
                    "gps_spoofing": bool(tx["gps_spoofing"]),
                    "remote_access_rat": bool(tx["remote_access_rat"]),
                    "typing_cadence_score": int(tx["typing_cadence_score"]),
                },
            }
        )

    if st.session_state.automation_audit_log:
        st.markdown("##### 📜 Trilha de Auditoria das Automações Executadas na Sessão")
        safe_dataframe(pd.DataFrame(st.session_state.automation_audit_log))


def main() -> None:
    st.set_page_config(
        page_title="Synapse Pix Shield — Antifraude-as-a-Service",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    init_session_state()

    user: Optional[AuthenticatedUser] = st.session_state.auth_user
    if user is None:
        render_login_screen()
        return

    inject_synapse_theme()
    tenant: B2BTenantConfig = st.session_state.b2b_tenant

    with st.sidebar:
        st.markdown("## 🛡️ SYNAPSE FaaS")
        st.markdown(f"**Usuário:** {user.full_name}")
        st.markdown(f'<span class="badge-role">Perfil RBAC: {user.role}</span>', unsafe_allow_html=True)
        st.caption(f"Tenant Ativo: `{tenant.company_name}`")
        st.caption(f"Fonte de Dados: `{st.session_state.data_source_label}`")
        engine_badge = "Plotly" if HAS_PLOTLY else ("Altair (Snowflake Native)" if HAS_ALTAIR else "SVG/HTML Native")
        st.caption(f"Motor Gráfico: `{engine_badge}`")

        if st.button("🚪 Encerrar Sessão (Logout)", use_container_width=True):
            st.session_state.auth_user = None
            safe_rerun()

        st.markdown("---")
        st.markdown("### ⚙️ Calibragem do Motor Pix")
        can_calibrate = user.has_permission("calibrate_weights")
        if not can_calibrate:
            st.info(f"🔒 Perfil **{user.role}**: Pesos em modo somente leitura.")

        w_curr: PixRiskWeights = st.session_state.risk_weights
        w_val = st.slider("Peso: Ruptura de Valor (x Média 30d)", 0, 40, w_curr.w_value_rupture, disabled=not can_calibrate)
        w_cpf = st.slider("Peso: Conflito Geográfico CPF x DDD", 0, 35, w_curr.w_cpf_ddd_mismatch, disabled=not can_calibrate)
        w_nig = st.slider("Peso: Janela Noturna (20h–06h)", 0, 30, w_curr.w_night_window, disabled=not can_calibrate)
        w_vel = st.slider("Peso: Velocidade / Pulverização 24h", 0, 35, w_curr.w_velocity_24h, disabled=not can_calibrate)
        w_dev = st.slider("Peso: Emulador / Root / VPN (SDK)", 0, 40, w_curr.w_device_emulator_vpn, disabled=not can_calibrate)
        w_key = st.slider("Peso: Chave Destino Recém-Criada", 0, 35, w_curr.w_new_pix_key, disabled=not can_calibrate)
        w_rat = st.slider("Peso: Mão Fantasma (RAT / Cadência)", 0, 35, w_curr.w_typing_cadence_rat, disabled=not can_calibrate)
        w_mul = st.slider("Peso: Anel Conta Laranja (Fan-In)", 0, 35, w_curr.w_fan_in_mule, disabled=not can_calibrate)

        if can_calibrate:
            st.session_state.risk_weights = PixRiskWeights(
                w_value_rupture=w_val,
                w_cpf_ddd_mismatch=w_cpf,
                w_night_window=w_nig,
                w_velocity_24h=w_vel,
                w_device_emulator_vpn=w_dev,
                w_new_pix_key=w_key,
                w_typing_cadence_rat=w_rat,
                w_geo_distance=w_curr.w_geo_distance,
                w_fan_in_mule=w_mul,
            )

        st.markdown("---")
        if st.button("🔄 Gerar Nova Amostra Pix (360 ops)", use_container_width=True):
            new_seed = secrets.randbelow(10_000)
            st.session_state.raw_pix_df = FeatureStoreRepository.generate_pix_dataset(360, seed=new_seed)
            st.session_state.data_source_label = f"Feature Store Sintética (Seed #{new_seed})"
            safe_rerun()

    st.markdown(
        f"""
        <div class="synapse-hero">
            <h1>🛡️ SYNAPSE — Primeiro Antifraude-as-a-Service (FaaS) para Golpes Pix com IA</h1>
            <p>Cockpit Executivo • Onboarding B2B com Token API (<code>{tenant.api_token_live[:22]}...</code>) • Clusterização de Contas Laranja • Validação Geográfica & Device Fingerprint SDK</p>
        </div>
        """,
        unsafe_allow_html=True,
    )

    df_scored = PixScoringEngine.score_dataframe(
        st.session_state.raw_pix_df,
        weights=st.session_state.risk_weights,
        tenant_policy=tenant,
    )

    tab_cockpit, tab_clusters_geo, tab_device_sdk, tab_csv_ai, tab_onboarding = st.tabs(
        [
            "📊 Cockpit Executivo (Storytelling)",
            "🕸️ Clusters & Análise Geográfica",
            "📱 Camada Dispositivo, Fingerprint & SDK",
            "🧠 Upload CSV, Score IA & Análise Individual",
            "🏢 Onboarding B2B & Token API",
        ]
    )

    with tab_cockpit:
        render_executive_cockpit(df_scored)

    with tab_clusters_geo:
        render_clusters_and_geography(df_scored)

    with tab_device_sdk:
        render_device_fingerprint_and_sdk(df_scored, tenant)

    with tab_csv_ai:
        render_csv_upload_and_individual_analysis(df_scored, user, tenant)

    with tab_onboarding:
        render_b2b_onboarding_page(user)


if __name__ == "__main__":
    main()
