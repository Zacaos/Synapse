
import streamlit as st
import pandas as pd
import numpy as np
import altair as alt
from datetime import datetime, timedelta
import random

st.set_page_config(page_title='Synapse Platform', page_icon='🛡️', layout='wide')

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
    
if "empresas" not in st.session_state:
    st.session_state.empresas = []

if "codigo_mfa" not in st.session_state:
    st.session_state.codigo_mfa = None

if "empresa_pendente" not in st.session_state:
    st.session_state.empresa_pendente = None

if "mfa_validado" not in st.session_state:
    st.session_state.mfa_validado = False



@st.cache_data
def gerar_dados():

    random.seed(42)
    np.random.seed(42)

    n = 3000

    cats = [
        'Conta OK',
        'Mule Account',
        'Application Fraud',
        'Scammer Account'
    ]

    df = pd.DataFrame({

        'transaction_id': [
            f'PIX{i}'
            for i in range(n)
        ],

        'timestamp': [
            datetime.now() -
            timedelta(
                hours=random.randint(0,720)
            )
            for _ in range(n)
        ],

        'pix_key': [
            f'cliente{i}@mail.com'
            for i in range(n)
        ],

        'cpf': [
            str(10000000000+i)
            for i in range(n)
        ],

        'documento': [
            f'RG{10000000+i}'
            for i in range(n)
        ],

        'telefone': [
            f'119{1000000+i}'
            for i in range(n)
        ],

        'email': [
            f'usuario{i}@email.com'
            for i in range(n)
        ],

        'amount': np.round(
            np.random.lognormal(
                6.5,
                1.1,
                n
            ),
            2
        ),

        'score': np.random.randint(
            1,
            100,
            n
        ),

        'destination': np.random.choice(
            [
                'E-commerce',
                'Pessoa Física',
                'Casa de Apostas',
                'Serviços'
            ],
            n,
            p=[0.5,0.3,0.15,0.05]
        )

    })

    df['categoria'] = np.random.choice(
        cats,
        n,
        p=[0.9,0.04,0.03,0.03]
    )


def decision(score):
    """Classifica o risco baseado no score"""
    if score >= 80:
        return 'Alto Risco'
    elif score >= 50:
        return 'Médio Risco'
    else:
        return 'Baixo Risco'


def obter_regiao(lat, lon):
    """Determina a região baseada em coordenadas"""
    for regiao, info in REGIOES_BRASIL.items():
        bounds = info['bounds']
        if bounds[1][0] <= lat <= bounds[0][0] and bounds[0][1] <= lon <= bounds[1][1]:
            return regiao
    return 'Fora do Brasil'


def buscar_por_campo(query, campo, df):
    """Busca genérica por qualquer campo"""
    resultado = df[df[campo].astype(str) == str(query)]
    return resultado if len(resultado) > 0 else None


def analisar_comportamento(dados_query, df, tipo_busca):
    """Analisa o comportamento baseado em qualquer tipo de busca"""
    
    if dados_query is None or len(dados_query) == 0:
        return None
    
    # Análises gerais
    num_transacoes = len(dados_query)
    valor_total = dados_query['amount'].sum()
    valor_medio = dados_query['amount'].mean()
    valor_max = dados_query['amount'].max()
    valor_min = dados_query['amount'].min()
    
    # Análise de destinos
    destinos = dados_query['destination'].value_counts()
    pct_apostas = (len(dados_query[dados_query['destination'] == 'Casa de Apostas']) / num_transacoes * 100) if num_transacoes > 0 else 0
    pct_ecommerce = (len(dados_query[dados_query['destination'] == 'E-commerce']) / num_transacoes * 100) if num_transacoes > 0 else 0
    
    # Análise de localização (Impossible Travel)
    locs = dados_query[['lat', 'lon', 'timestamp']].sort_values('timestamp')
    impossible_travel = False
    travel_warning = ""
    
    if len(locs) > 1:
        for i in range(1, len(locs)):
            lat1, lon1 = locs.iloc[i-1]['lat'], locs.iloc[i-1]['lon']
            lat2, lon2 = locs.iloc[i]['lat'], locs.iloc[i]['lon']
            time_diff = (locs.iloc[i]['timestamp'] - locs.iloc[i-1]['timestamp']).total_seconds() / 3600
            
            # Cálculo simples de distância (haversine aproximado)
            distance = np.sqrt((lat2-lat1)**2 + (lon2-lon1)**2) * 111  # ~111km por grau
            
            if time_diff > 0 and distance / time_diff > 800:  # Acima de 800km/h é impossível
                impossible_travel = True
                travel_warning = f"⚠️ Viagem impossível detectada: {distance:.0f}km em {time_diff:.1f}horas"
    
    # Score médio e risco
    score_medio = dados_query['score'].mean()
    risco = decision(score_medio)
    
    # Detectar região
    regiao = obter_regiao(dados_query['lat'].mean(), dados_query['lon'].mean())
    
    return {
        'num_transacoes': num_transacoes,
        'valor_total': valor_total,
        'valor_medio': valor_medio,
        'valor_max': valor_max,
        'valor_min': valor_min,
        'destinos': destinos,
        'pct_apostas': pct_apostas,
        'pct_ecommerce': pct_ecommerce,
        'score_medio': score_medio,
        'risco': risco,
        'impossible_travel': impossible_travel,
        'travel_warning': travel_warning,
        'dados_detalhados': dados_query,
        'tipo_busca': tipo_busca,
        'regiao': regiao
    }


def login():
    st.title('🔐 Synapse Platform')
    u=st.text_input('Usuário')
    p=st.text_input('Senha',type='password')
    perfil=st.selectbox('Perfil',['Administrador','Analista','Auditor','Suporte'])
    if st.button('Entrar'):
        if u and p:
            st.session_state.authenticated=True
            st.session_state.user=u
            st.session_state.perfil=perfil
            st.rerun()
        else:
            st.error('Informe usuário e senha')

if not st.session_state.authenticated:
    login(); st.stop()

#Titulo centralizado

col1, col2, col3 = st.columns([1, 2, 1])

with col2:
    st.title("🛡️ Synapse Pix Antifraude")
    st.title("Análise preditiva com IA")


# MENU HORIZONTAL

st.markdown("""
<style>

div.stButton > button {
    height: 50px;
    border-radius: 12px;
    border: 1px solid #1E3A8A;
    background-color: #2563EB;
    color: white;
    font-weight: bold;
}

div.stButton > button:hover {
    background-color: #1E40AF;
    color: white;
}

</style>
""", unsafe_allow_html=True)

col1, col2, col3 = st.columns(3)

if "menu" not in st.session_state:
    st.session_state.menu = "Synapse Dashboard"

with col1:
    if st.button("📊 Dashboard", use_container_width=True):
        st.session_state.menu = "Synapse Dashboard"

with col2:
    if st.button("🧠 IA Análise de Score", use_container_width=True):
        st.session_state.menu = "IA Análise de Score"

with col3:
    if st.button("Quem Somos", use_container_width=True):
        st.session_state.menu = "Quem Somos"


menu = st.session_state.menu


DF=gerar_dados()

st.sidebar.write(f"Usuário: {st.session_state.user}")
st.sidebar.write(f"Perfil: {st.session_state.perfil}")



if menu=='Synapse Dashboard':
    st.title('Synapse Dashboard')
    c1,c2,c3,c4,c5,c6=st.columns(6)
if "amount" in DF.columns:
    c1.metric(
        "TPV",
        f"R$ {DF['amount'].sum():,.0f}"
    )
else:
    c1.error(
        f"Coluna 'amount' não encontrada. Colunas disponíveis: {list(DF.columns)}"
    )
    c2.metric('Contas',len(DF))
    c3.metric('Suspeitas',len(DF[DF.categoria!='Conta OK']))
    c4.metric('Mule',len(DF[DF.categoria=='Mule Account']))
    c5.metric('Scammer',len(DF[DF.categoria=='Scammer Account']))
    c6.metric('Score Médio',round(DF.score.mean(),1))

    tmp=DF.copy(); tmp['dia']=pd.to_datetime(tmp.timestamp).dt.date
    grp=tmp.groupby(['dia','categoria'])['amount'].sum().reset_index()
    st.subheader('TPV por Categoria')
    st.altair_chart(alt.Chart(grp).mark_bar().encode(x='dia:T',y='amount:Q',color='categoria:N'),use_container_width=True)

    linha=tmp.groupby('dia').size().reset_index(name='volume')
    st.subheader('Volume de Chaves Suspeitas')
    st.altair_chart(alt.Chart(linha).mark_line(point=True).encode(x='dia:T',y='volume:Q'),use_container_width=True)

    donut=DF['categoria'].value_counts().reset_index()
    donut.columns=['categoria','valor']
    st.subheader('Distribuição por Categoria')
    st.altair_chart(alt.Chart(donut).mark_arc(innerRadius=70).encode(theta='valor:Q',color='categoria:N'),use_container_width=True)

    st.subheader('Transações Monitoradas')
    st.dataframe(DF.head(100),use_container_width=False);




elif menu == "Quem Somos":

    st.title("Quem Somos")

    st.markdown("""
# Synapse Fraud Prevention

A **Synapse Fraud Prevention** é uma iniciativa em fase de desenvolvimento, criada para acompanhar a evolução do ecossistema Pix e contribuir para um ambiente financeiro mais seguro, eficiente e confiável.

Nascemos com o propósito de unir tecnologia, análise de dados e inteligência antifraude para apoiar instituições e empresas na prevenção de riscos em transações instantâneas.

Estamos vivendo uma fase de construção e aprendizado contínuo, observando atentamente o crescimento do Pix, as novas modalidades de pagamento, as tendências de fraude e as inovações promovidas pelo Banco Central do Brasil. Nossa visão é desenvolver soluções que ajudem o mercado a se adaptar rapidamente às mudanças regulatórias e aos novos desafios de segurança.

A Synapse busca transformar dados em inteligência acionável, permitindo identificar padrões suspeitos, antecipar ameaças e fortalecer mecanismos de prevenção à fraude. Além disso, acompanhamos de perto a evolução das normas e regulamentações do Banco Central, incluindo a **Resolução BCB nº 142** e demais iniciativas voltadas ao aprimoramento da segurança, governança e eficiência do ecossistema Pix.

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

### Synapse Fraud Prevention

*Antecipando riscos, fortalecendo a confiança e apoiando o futuro seguro do Pix.* 🚀🔒📊
""")

