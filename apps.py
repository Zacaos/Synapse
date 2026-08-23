import streamlit as st
import pandas as pd
import numpy as np
import altair as alt
from datetime import datetime, timedelta
import random

# ==================================================
# CONFIG
# ==================================================

st.set_page_config(
    page_title="Synapse Fraud Prevention",
    page_icon="🛡️",
    layout="wide"
)

# ==================================================
# LOGIN
# ==================================================

if "authenticated" not in st.session_state:
    st.session_state.authenticated = False


def login():

    st.title("🛡️ Synapse Fraud Prevention")

    user = st.text_input("Usuário")

    password = st.text_input(
        "Senha",
        type="password"
    )

    perfil = st.selectbox(
        "Perfil",
        [
            "Administrador",
            "Analista",
            "Auditor"
        ]
    )

    if st.button("Entrar"):

        if user and password:

            st.session_state.authenticated = True
            st.session_state.user = user
            st.session_state.perfil = perfil

            st.rerun()

        else:

            st.error(
                "Informe usuário e senha."
            )


if not st.session_state.authenticated:
    login()
    st.stop()

# ==================================================
# DADOS
# ==================================================

@st.cache_data
def gerar_dados():

    random.seed(42)
    np.random.seed(42)

    n = 3000

    categorias = [
        "Conta OK",
        "Mule Account",
        "Application Fraud",
        "Scammer Account"
    ]

    df = pd.DataFrame({

        "transaction_id":[
            f"PIX{i}"
            for i in range(n)
        ],

        "timestamp":[
            datetime.now()
            - timedelta(
                hours=random.randint(0,720)
            )
            for _ in range(n)
        ],

        "pix_key":[
            f"cliente{i}@mail.com"
            for i in range(n)
        ],

        "cpf":[
            str(10000000000+i)
            for i in range(n)
        ],

        "documento":[
            f"RG{10000000+i}"
            for i in range(n)
        ],

        "telefone":[
            f"119{1000000+i}"
            for i in range(n)
        ],

        "email":[
            f"usuario{i}@email.com"
            for i in range(n)
        ],

        "amount":np.round(
            np.random.lognormal(
                6.5,
                1.1,
                n
            ),
            2
        ),

        "score":np.random.randint(
            1,
            100,
            n
        )

    })

    df["categoria"] = np.random.choice(
        categorias,
        n,
        p=[0.90,0.04,0.03,0.03]
    )

    return df


DF = gerar_dados()

# ==================================================
# HEADER
# ==================================================

col1, col2, col3 = st.columns([1,2,1])

with col2:

    st.title(
        "🛡️ Synapse Fraud Prevention"
    )

    st.caption(
        "Análise preditiva com IA e monitoramento de risco Pix"
    )

# ==================================================
# MENU
# ==================================================

st.markdown("""
<style>

div.stButton > button {
    height:50px;
    border-radius:12px;
    background-color:#2563EB;
    color:white;
    font-weight:bold;
}

</style>
""", unsafe_allow_html=True)

m1, m2, m3, m4 = st.columns(4)

if "menu" not in st.session_state:
    st.session_state.menu = "Dashboard"

with m1:

    if st.button(
        "📊 Dashboard",
        use_container_width=True
    ):

        st.session_state.menu = "Dashboard"

with m2:

    if st.button(
        "🧠 IA Análise de Score",
        use_container_width=True
    ):

        st.session_state.menu = "IA"

with m3:

    if st.button(
        "ℹ️ Quem Somos",
        use_container_width=True
    ):
        st.session_state.menu = "Quem Somos"

with m4:

    if st.button(
        "📖 Ajuda",
        use_container_width=True
    ):

        st.session_state.menu = "Ajuda"        

menu = st.session_state.menu

# ==================================================
# SIDEBAR
# ==================================================

st.sidebar.write(
    f"Usuário: {st.session_state.user}"
)

st.sidebar.write(
    f"Perfil: {st.session_state.perfil}"
)

# ==================================================
# DASHBOARD
# ==================================================

if menu == "Dashboard":

    st.subheader("Dashboard Executivo")

    c1,c2,c3,c4,c5,c6 = st.columns(6)

    c1.metric(
        "TPV",
        f"R$ {DF['amount'].sum():,.0f}"
    )

    c2.metric(
        "Contas",
        len(DF)
    )

    c3.metric(
        "Suspeitas",
        len(
            DF[
                DF["categoria"] != "Conta OK"
            ]
        )
    )

    c4.metric(
        "Mule",
        len(
            DF[
                DF["categoria"]=="Mule Account"
            ]
        )
    )

    c5.metric(
        "Scammer",
        len(
            DF[
                DF["categoria"]=="Scammer Account"
            ]
        )
    )

    c6.metric(
        "Score Médio",
        round(
            DF["score"].mean(),
            1
        )
    )

    tmp = DF.copy()

    tmp["dia"] = pd.to_datetime(
        tmp["timestamp"]
    ).dt.date

    grp = (
        tmp.groupby(
            ["dia","categoria"]
        )["amount"]
        .sum()
        .reset_index()
    )

    st.subheader(
        "TPV por Categoria"
    )

    st.altair_chart(
        alt.Chart(grp)
        .mark_bar()
        .encode(
            x="dia:T",
            y="amount:Q",
            color="categoria:N"
        ),
        use_container_width=True
    )

    donut=DF['categoria'].value_counts().reset_index()
    donut.columns=['categoria','valor']
    st.subheader('Distribuição por Categoria')
    st.altair_chart(alt.Chart(donut).mark_arc(innerRadius=70).encode(theta='valor:Q',color='categoria:N'),use_container_width=True)
    st.subheader(
        "Transações Monitoradas"
    )

    st.dataframe(
        DF.head(100),
        use_container_width=True
    )

# ==================================================
# IA SCORE
# ==================================================

elif menu == "IA":

    st.subheader("🧠 IA Análise de Score")

    tipo = st.selectbox(
        "Tipo de Consulta",
        [
            "CPF",
            "Documento",
            "Telefone",
            "E-mail",
            "Chave Pix",
            "Aleatória"
        ]
    )

    valor = ""

    if tipo != "Aleatória":

        valor = st.text_input(
            "Informe o identificador"
        )

    if st.button("Consultar"):

        if tipo == "Aleatória":

            resultado = DF.sample(1)

        else:

            mapa = {

                "CPF": "cpf",
                "Documento": "documento",
                "Telefone": "telefone",
                "E-mail": "email",
                "Chave Pix": "pix_key"
            }

            campo = mapa[tipo]

            resultado = DF[
                DF[campo]
                .astype(str)
                .str.lower()
                ==
                valor.strip().lower()
            ]

        if len(resultado) > 0:

            registro = resultado.iloc[0]

            st.session_state["registro"] = (
                registro.to_dict()
            )

        else:

            st.error(
                "❌ Registro não encontrado"
            )

    # ==========================================
    # RESULTADO
    # ==========================================

    if "registro" in st.session_state:

        registro = st.session_state["registro"]

        score = int(registro["score"])

        valor_transacao = float(
            registro["amount"]
        )

        categoria = registro["categoria"]

        st.success(
            "✅ Registro localizado"
        )

        c1, c2, c3 = st.columns(3)

        c1.metric(
            "Score",
            score
        )

        c2.metric(
            "Valor",
            f"R$ {valor_transacao:,.2f}"
        )

        c3.metric(
            "Categoria",
            categoria
        )

        # ==========================================
        # RISK LEVEL
        # ==========================================

        st.subheader("🎯 Risk Level")

        if score < 50:

            st.success(
                "🟢 BAIXO RISCO"
            )

        elif score < 80:

            st.warning(
                "🟡 MÉDIO RISCO"
            )

        else:

            st.error(
                "🔴 ALTO RISCO"
            )

        # ==========================================
        # AGENTE IA
        # ==========================================

        st.divider()

        st.subheader(
            "🤖 Agente IA"
        )

        recomendacoes = []

        


        
        
        
        if score >= 80:

            recomendacoes.append(
                "🚨 Score elevado identificado."
            )

        elif score >= 50:

            recomendacoes.append(
                "⚠️ Recomenda-se MFA."
            )

        else:

            recomendacoes.append(
                "✅ Perfil dentro do padrão."
            )

        if categoria != "Conta OK":

            recomendacoes.append(
                f"Categoria: {categoria}"
            )

        if valor_transacao > 1000:

            recomendacoes.append(
                "Valor acima de R$ 1.000,00."
            )

        for r in recomendacoes:

            st.info(r)

        st.divider()

        # ==========================================
        # DECISÃO
        # ==========================================

        if score < 50:

            st.success(
                "✅ APPROVE"
            )

        elif score < 80:

            st.warning(
                "🔐 MFA RECOMENDADO"
            )

        else:

            st.error(
                "⛔ BLOQUEIO CAUTELAR RECOMENDADO"
            )

        col1, col2, col3 = st.columns(3)

        with col1:

            if st.button(
                "🔐 Solicitar MFA"
            ):

                st.success(
                    "MFA enviado."
                )

        with col2:

            if st.button(
                "⛔ Bloqueio Cautelar"
            ):

                protocolo = (
                    f"BLOQ-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                )

                st.success(
                    f"Bloqueio registrado: {protocolo}"
                )

        with col3:

            if st.button(
                "🚨 Abrir MED"
            ):

                protocolo = (
                    f"MED-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                )

                st.success(
                    f"Contestação criada: {protocolo}"
                )

# ==================================================
# QUEM SOMOS
# ==================================================

# ==================================================
# AJUDA
# ==================================================

elif menu == "Ajuda":

    st.title("📖 Guia de Utilização")

    st.markdown("""
# Synapse Fraud Prevention

Esta funcionalidade permite testar a análise de risco utilizando dados simulados gerados para demonstração do MVP.

---

## 🔍 Tipos de Consulta

O sistema permite pesquisas utilizando:

### CPF

Exemplos:

10000000000

10000000001

10000000002

---

### Documento

Exemplos:

RG10000000

RG10000001

RG10000002

---

### Telefone

Exemplos:

1191000000

1191000001

1191000002

---

### E-mail

Exemplos:

usuario0@email.com

usuario1@email.com

usuario2@email.com

---

### Chave Pix

Exemplos:

cliente0@mail.com

cliente1@mail.com

cliente2@mail.com

---

### Consulta Aleatória

Seleciona automaticamente um registro da base simulada.

---

## 🤖 Resultado da Análise

Após a consulta o sistema exibe:

- Score
- Valor da operação
- Categoria
- Risk Level
- Recomendações da IA

---

## 🎯 Risk Level

### 🟢 Baixo Risco

Score entre:

1 e 49

Ação sugerida:

✅ APPROVE

---

### 🟡 Médio Risco

Score entre:

50 e 79

Ação sugerida:

🔐 MFA

---

### 🔴 Alto Risco

Score entre:

80 e 99

Ação sugerida:

⛔ Bloqueio Cautelar

---

## 🤖 Agente IA

O agente avalia:

- Score
- Categoria
- Valor da transação

E gera recomendações automáticas para apoio à tomada de decisão.

---

## 🔐 MFA

MFA (Multi-Factor Authentication)

Pode representar:

- OTP
- Token
- Biometria
- Push Notification

---

## ⛔ Bloqueio Cautelar

Permite reter a operação para validação adicional em situações de risco elevado.

---

## 🚨 Contestação MED

O sistema permite simular a abertura de uma contestação MED.

Exemplo:

MED-20260822153000

---

## ⚠️ Importante

Todos os dados exibidos foram gerados artificialmente para fins acadêmicos e demonstração do MVP da Synapse Fraud Prevention.
""")



elif menu == "Quem Somos":

    st.title("🛡️ Quem Somos")

    
    st.markdown("""

# Synapse Fraud Prevention

A **Synapse Fraud Prevention** é uma iniciativa em fase de desenvolvimento, criada para acompanhar a evolução do ecossistema Pix e contribuir para um ambiente financeiro mais seguro, eficiente e confiável.

Nascemos com o propósito de unir tecnologia, análise de dados e inteligência antifraude para apoiar instituições e empresas na prevenção de riscos em transações instantâneas.

Estamos vivendo uma fase de construção e aprendizado contínuo, observando atentamente o crescimento do Pix, as novas modalidades de pagamento, as tendências de fraude e as inovações promovidas pelo Banco Central do Brasil.

Nossa visão é desenvolver soluções que ajudem o mercado a se adaptar rapidamente às mudanças regulatórias e aos novos desafios de segurança.

A Synapse busca transformar dados em inteligência acionável, permitindo identificar padrões suspeitos, antecipar ameaças e fortalecer mecanismos de prevenção à fraude.

Além disso, acompanhamos de perto a evolução das normas e regulamentações do Banco Central, incluindo a Resolução BCB nº 142 e demais iniciativas voltadas ao aprimoramento da segurança, governança e eficiência do ecossistema Pix.

Acreditamos que inovação e segurança devem caminhar juntas. Por isso, estamos construindo uma plataforma preparada para apoiar instituições financeiras, fintechs, empresas e participantes do sistema de pagamentos instantâneos na gestão de riscos e na conformidade regulatória.

## 🎯 Nossa Missão

Desenvolver soluções inteligentes de prevenção à fraude para fortalecer a confiança e a segurança nas transações Pix.

## 🚀 Nossa Visão

Ser referência em inteligência antifraude para pagamentos instantâneos, acompanhando a evolução regulatória e tecnológica do mercado financeiro brasileiro.

## 💎 Nossos Valores

- 🔒 Segurança em primeiro lugar
- 🚀 Inovação contínua
- 🤝 Transparência e ética
- ✅ Conformidade regulatória
- 📊 Inteligência baseada em dados
- 🌐 Colaboração com o ecossistema financeiro

---

## O que este protótipo demonstra

✅ Dashboard de monitoramento Pix

✅ Análise comportamental baseada em IA

✅ Identificação de padrões de risco

✅ Risk Scoring

✅ Recomendações de prevenção

✅ Simulação de bloqueio cautelar

✅ Contestação MED

✅ Avaliação comportamental de chaves Pix

✅ Monitoramento de contas suspeitas

---

### 🚀 Roadmap

Futuras evoluções da plataforma:

- Machine Learning supervisionado
- Detecção de anomalias em tempo real
- Integração com Snowflake
- Explainable AI
- Monitoring Engine
- Model Registry
- Score Transacional Pix
- Risk Decision Engine
- Integração com indicadores regulatórios

---

### Synapse Fraud Prevention

*Antecipando riscos. Fortalecendo a confiança. Protegendo o futuro do Pix.* 🛡️🚀📊
""")            
