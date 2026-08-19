
import streamlit as st
import pandas as pd
import numpy as np
import altair as alt
from datetime import datetime, timedelta
import random

st.set_page_config(page_title='Synapse Platform', page_icon='🛡️', layout='wide')

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

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

@st.cache_data
def gerar_dados():
    random.seed(42)
    np.random.seed(42)
    n=3000
    cats=['Conta OK','Mule Account','Application Fraud','Scammer Account']
    df=pd.DataFrame({
      'transaction_id':[f'PIX{i}' for i in range(n)],
      'timestamp':[datetime.now()-timedelta(hours=random.randint(0,720)) for _ in range(n)],
      'pix_key':[f'cliente{i}@mail.com' for i in range(n)],
      'cpf':[str(10000000000+i) for i in range(n)],
      'amount':np.round(np.random.lognormal(6.5,1.1,n),2),
      'score':np.random.randint(1,100,n),
      'lat':np.random.uniform(-33,5,n),
      'lon':np.random.uniform(-73,-34,n)
    })
    df['categoria']=np.random.choice(cats,n,p=[0.9,0.04,0.03,0.03])
    return df


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

DF=gerar_dados()

st.sidebar.title('🛡️ Synapse')
st.sidebar.write(f"Usuário: {st.session_state.user}")
st.sidebar.write(f"Perfil: {st.session_state.perfil}")
# MENU HORIZONTAL

col1, col2, col3 = st.columns(3)

if "menu" not in st.session_state:
    st.session_state.menu = "Synapse Dashboard"

with col1:
    if st.button("📊 Dashboard", use_container_width=True):
        st.session_state.menu = "Synapse Dashboard"

with col2:
    if st.button("🧠 IA Score", use_container_width=True):
        st.session_state.menu = "IA Análise de Score"

#with col3:
 #   if st.button("🔍 Transações", use_container_width=True):
  #      st.session_state.menu = "Transações Monitoradas"

with col3:
    if st.button("ℹ️ Quem Somos", use_container_width=True):
        st.session_state.menu = "Quem Somos"

menu = st.session_state.menu

st.sidebar.divider()
st.sidebar.info('Suporte 24x7 suporte@synapse.com')

if menu=='Synapse Dashboard':
    st.title('Synapse Dashboard')
    c1,c2,c3,c4,c5,c6=st.columns(6)
    c1.metric('TPV',f"R$ {DF.amount.sum():,.0f}")
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
    st.dataframe(DF.head(100),use_container_width=True)



elif menu == 'IA Análise de Score':

    st.title("🔍 Análse por chave Pix")

    

    modo = st.radio(
        "Modo de Operação",
        ["Produção","Shadow Mode"]
    )

    st.divider()

    c1,c2 = st.columns(2)

    with c1:

        valor = st.number_input(
            "Valor da Transação",
            min_value=0.0,
            value=1500.00,
            step=100.0
        )

        destinatario = st.text_input(
            "Favorecido",
            "João da Silva"
        )

        chave_pix = st.text_input(
            "Chave Pix",
            "11999999999"
        )

    with c2:

        media_7dias = st.number_input(
            "Média dos últimos 7 dias",
            value=450.00
        )

        destino_conhecido = st.checkbox(
            "Destinatário conhecido",
            False
        )

        novo_dispositivo = st.checkbox(
            "Novo dispositivo",
            True
        )

        dict_flag = st.checkbox(
            "DICT Fraud Marker",
            True
        )

    if st.button("🔎 Analisar Transação"):

        score = 1

        if valor > 1000:
            score += 20

        if valor > media_7dias * 2:
            score += 20

        if not destino_conhecido:
            score += 25

        if novo_dispositivo:
            score += 15

        if dict_flag:
            score += 18

        score = min(score,99)

        st.divider()

        st.subheader("Resultado da Análise")

        c1,c2,c3 = st.columns(3)

        c1.metric("Score Synapse",score)

        if score <= 30:

            risco = "BAIXO"

            c2.success("✅ Baixo Risco")

            decisao = "APPROVE"

        elif score <= 70:

            risco = "MÉDIO"

            c2.warning("⚠️ Médio Risco")

            decisao = "CHALLENGE"

        else:

            risco = "ALTO"

            c2.error("🚨 Alto Risco")

            decisao = "BLOCK"

        c3.metric(
            "Recomendação",
            decisao
        )

        if valor > media_7dias:

            st.warning(f"""
            Esta transação possui valor acima da média dos últimos 7 dias.

            Média histórica: R$ {media_7dias:,.2f}

            Valor atual: R$ {valor:,.2f}
            """)

        st.divider()

        st.subheader("🤖 Agente de Recomendações Pix")

        recomendacoes = []

        if not destino_conhecido:
            recomendacoes.append(
                "Destinatário não identificado no histórico do cliente."
            )

        if valor > media_7dias:
            recomendacoes.append(
                "Valor superior ao padrão transacional recente."
            )

        if novo_dispositivo:
            recomendacoes.append(
                "Novo dispositivo detectado."
            )

        if dict_flag:
            recomendacoes.append(
                "Existem marcadores de risco associados ao ecossistema Pix."
            )

        for item in recomendacoes:
            st.info(item)

        st.markdown("""
### Perguntas de Segurança

✅ Você conhece o recebedor?

✅ O pagamento foi solicitado por telefone?

✅ Existe urgência para realizar esta transferência?

✅ O favorecido foi validado por outro canal?
        """)

        st.divider()

        st.subheader("🔐 MFA - Validação Reforçada")

        mfa = st.checkbox(
            "Solicitar MFA"
        )

        if mfa:

            st.success(
                "OTP / Biometria Facial solicitados ao usuário."
            )

        st.divider()

        st.subheader("⛔ Bloqueio Cautelar")

        if score > 70:

            st.error("""
Possível tentativa de fraude identificada.

Conforme políticas internas de prevenção à fraude
e mecanismos de monitoramento transacional,
recomenda-se a aplicação de bloqueio cautelar
para validação adicional da operação.
            """)

            if st.button(
                "Aplicar Bloqueio Cautelar"
            ):

                st.success("""
Transação encaminhada para validação.

Prazo máximo de análise:
24 horas.
                """)

        st.divider()

        st.subheader("🚨 Contestação MED")

        if st.button(
            "Abrir Contestação MED"
        ):

            protocolo = (
                f"MED-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            )

            st.success(
                f"Contestação criada: {protocolo}"
            )

        if modo == "Shadow Mode":

            st.info("""
SHADOW MODE ATIVO

O score foi calculado normalmente.

Nenhuma ação operacional será aplicada.

As decisões são registradas apenas para análise do modelo.
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
