
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

    return df


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
    if st.button(" ℹ️Quem Somos", use_container_width=True):
        st.session_state.menu = "Quem somos"


menu = st.session_state.menu


DF=gerar_dados()

st.sidebar.title('🛡️Synapse Pix Antifraude')
st.sidebar.write(f"Usuário: {st.session_state.user}")
st.sidebar.write(f"Perfil: {st.session_state.perfil}")



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
    st.dataframe(DF.head(100),use_container_width=False);


    
###Análise comportamental por tipo de chave Pix

elif menu=='IA Análise de Score':
    st.title('🔍 IA Análise Score Pix')
    
    st.subheader('📋 Análise Comportamental com IA')
    
    # Seleção do tipo de busca
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        tipo_cpf = st.checkbox('📋 CPF', value=False)
    with col2:
        tipo_pix = st.checkbox('🔑 Chave Pix', value=False)
    with col3:
        tipo_doc = st.checkbox('🆔 Documento', value=False)
    with col4:
        tipo_email = st.checkbox('📧 E-mail', value=False)
    
    col5, col6, col7 = st.columns(3)
    with col5:
        tipo_tel = st.checkbox('📱 Telefone', value=False)
    with col6:
        tipo_aleatorio = st.checkbox('🎲 Aleatória', value=False)
    with col7:
        tipo_e2e = st.checkbox('🔗 E2E (Todos os campos)', value=False)
    
    st.divider()
    
    # Entrada de dados
    col_entrada1, col_entrada2 = st.columns([3, 1])
    
    with col_entrada1:
        if tipo_cpf:
            entrada = st.text_input('Digite o CPF', placeholder='Ex: 10000000000', key='cpf_input')
            tipo_selecionado = 'cpf'
        elif tipo_pix:
            entrada = st.text_input('Digite a Chave Pix', placeholder='Ex: cliente0@mail.com', key='pix_input')
            tipo_selecionado = 'pix_key'
        elif tipo_doc:
            entrada = st.text_input('Digite o Documento (RG)', placeholder='Ex: RG10000000', key='doc_input')
            tipo_selecionado = 'documento'
        elif tipo_tel:
            entrada = st.text_input('Digite o Telefone', placeholder='Ex: 11900000000', key='tel_input')
            tipo_selecionado = 'telefone'
        elif tipo_email:
            entrada = st.text_input('Digite o E-mail', placeholder='Ex: usuario0@email.com', key='email_input')
            tipo_selecionado = 'email'
        elif tipo_e2e:
            entrada = st.text_input('Digite qualquer identificador', placeholder='Ex: usuario0@email.com', key='e2e_input')
            tipo_selecionado = 'e2e'
        else:
            entrada = None
            tipo_selecionado = None
    
    with col_entrada2:
        if tipo_aleatorio:
            btn_submit = st.button('🎲 Consultar', use_container_width=True)
        else:
            btn_submit = st.button('🔍 Consultar', use_container_width=True)
    
    resultado = None


  
    if btn_submit:
        if tipo_aleatorio:
            indice_aleatorio = np.random.randint(0, len(DF))
            registro_aleatorio = DF.iloc[indice_aleatorio]
            cpf_aleatorio = registro_aleatorio['cpf']
            resultado = analisar_comportamento(buscar_por_campo(cpf_aleatorio, 'cpf', DF), DF, 'CPF (Aleatória)')
            st.info(f"📊 CPF selecionado aleatoriamente: **{cpf_aleatorio}**")
        elif tipo_e2e and entrada:
            # Busca em múltiplos campos
            resultado_cpf = buscar_por_campo(entrada, 'cpf', DF)
            resultado_pix = buscar_por_campo(entrada, 'pix_key', DF) if resultado_cpf is None else None
            resultado_doc = buscar_por_campo(entrada, 'documento', DF) if resultado_pix is None else None
            resultado_tel = buscar_por_campo(entrada, 'telefone', DF) if resultado_doc is None else None
            resultado_email = buscar_por_campo(entrada, 'email', DF) if resultado_tel is None else None
            
            resultado_final = resultado_cpf if resultado_cpf is not None else (
                resultado_pix if resultado_pix is not None else (
                    resultado_doc if resultado_doc is not None else (
                        resultado_tel if resultado_tel is not None else resultado_email
                    )
                )
            )
            
            if resultado_final is not None:
                tipo_encontrado = 'CPF' if resultado_cpf is not None else (
                    'Chave Pix' if resultado_pix is not None else (
                        'Documento' if resultado_doc is not None else (
                            'Telefone' if resultado_tel is not None else 'E-mail'
                        )
                    )
                )
                resultado = analisar_comportamento(resultado_final, DF, f'{tipo_encontrado} (E2E)')
            else:
                st.warning(f'❌ Nenhuma correspondência encontrada para: {entrada}')
        elif entrada and tipo_selecionado and tipo_selecionado != 'e2e':
            resultado = analisar_comportamento(buscar_por_campo(entrada, tipo_selecionado, DF), DF, tipo_selecionado.upper())
            if resultado is None:
                st.warning(f'❌ Nenhum resultado encontrado. Verifique o identificador e tente novamente.')
        else:
            st.warning('⚠️ Por favor, selecione um tipo de busca e informe um valor válido.')
    
    # Exibição de resultados
    if resultado is not None:
        st.success(f'✅ Encontrado por: {resultado["tipo_busca"]} | Região: **{resultado["regiao"]}**')
        
        # Indicador de risco
        if resultado['risco'] == 'Alto Risco':
            st.error(f"⚠️ **RISCO ALTO** - Score Médio: {resultado['score_medio']:.1f}")
        elif resultado['risco'] == 'Médio Risco':
            st.warning(f"⚠️ **RISCO MÉDIO** - Score Médio: {resultado['score_medio']:.1f}")
        else:
            st.success(f"✅ **RISCO BAIXO** - Score Médio: {resultado['score_medio']:.1f}")
        
        st.divider()
        
        # Métricas principais
        col1, col2, col3, col4 = st.columns(4)
        col1.metric('📊 Transações', resultado['num_transacoes'])
        col2.metric('💰 Valor Total', f"R$ {resultado['valor_total']:,.2f}")
        col3.metric('📈 Valor Médio', f"R$ {resultado['valor_medio']:,.2f}")
        col4.metric('🔝 Valor Máximo', f"R$ {resultado['valor_max']:,.2f}")
        
        st.divider()
        
        # Análise de destinos
        st.subheader('🎯 Análise de Destinos')
        col_dest1, col_dest2, col_dest3 = st.columns(3)
        col_dest1.metric('🏬 E-commerce', f"{resultado['pct_ecommerce']:.1f}%")
        col_dest2.metric('🎰 Casa de Apostas', f"{resultado['pct_apostas']:.1f}%", 
                       delta=None if resultado['pct_apostas'] == 0 else f"⚠️ Alto Risco" if resultado['pct_apostas'] > 20 else None)
        col_dest3.metric('👤 Pessoa Física', f"{(100-resultado['pct_ecommerce']-resultado['pct_apostas']):.1f}%")
        
        # Gráfico de destinos
        if len(resultado['destinos']) > 0:
            chart_data = resultado['destinos'].reset_index()
            chart_data.columns = ['Destino', 'Quantidade']
            st.bar_chart(chart_data.set_index('Destino'))
        
        st.divider()
        
        # Análise de Impossible Travel
        st.subheader('✈️ Análise de Impossible Travel')
        if resultado['impossible_travel']:
            st.error(resultado['travel_warning'])
            st.info('Comportamento suspeito detectado: transações em locais geograficamente distantes em um curto período de tempo.')
        else:
            st.success('✅ Nenhuma atividade de viagem impossível detectada')
        
        st.divider()
        
        # Análise de comportamento e sentido
        st.subheader('🧠 Análise de Comportamento')
        
        comportamento_text = ""
        bandeiras_vermelhas = []
        
        if resultado['pct_apostas'] > 20:
            bandeiras_vermelhas.append(f"⚠️ Alto percentual de transações para casas de apostas ({resultado['pct_apostas']:.1f}%)")
        
        if resultado['pct_ecommerce'] > 70 and resultado['valor_medio'] < 100:
            comportamento_text += "✅ Comportamento consistente: compras frequentes e pequenas em e-commerce\n"
        elif resultado['pct_ecommerce'] > 70 and resultado['valor_medio'] > 500:
            bandeiras_vermelhas.append("⚠️ Grandes compras em e-commerce podem indicar compras fraudulentas")
        
        if resultado['valor_max'] > resultado['valor_medio'] * 10:
            bandeiras_vermelhas.append(f"⚠️ Transação anormalmente alta: R$ {resultado['valor_max']:,.2f} vs média R$ {resultado['valor_medio']:,.2f}")
        
        if bandeiras_vermelhas:
            st.warning("🚩 **Bandeiras Vermelhas Detectadas:**")
            for bandeira in bandeiras_vermelhas:
                st.write(bandeira)
        else:
            st.success("✅ Nenhuma bandeira vermelha detectada no padrão comportamental")
        
        if comportamento_text:
            st.info(comportamento_text)
        
        st.divider()
        
        # Tabela detalhada
        st.subheader('📑 Histórico de Transações')
        st.dataframe(resultado['dados_detalhados'].sort_values('timestamp', ascending=False), use_container_width=True)




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
# Pix Synapse Fraud Prevention

O **Pix Synapse Fraud Prevention** é um protótipo desenvolvido com o objetivo de demonstrar como modelos de Inteligência Artificial, Machine Learning e análise transacional podem auxiliar na prevenção de fraudes no ecossistema Pix.

## Nossa Visão

Acreditamos que a prevenção à fraude deve acontecer antes que o prejuízo ocorra.

Por isso, buscamos criar mecanismos capazes de analisar transações em tempo real, identificar comportamentos suspeitos e apoiar instituições financeiras na tomada de decisão.

---

## O Problema

O crescimento do Pix trouxe mais inclusão financeira, velocidade e conveniência.

Ao mesmo tempo, também gerou novos desafios relacionados a:

- Engenharia Social
- Contas Laranja (Mule Accounts)
- Account Takeover
- Application Fraud
- Golpes de falsa central
- Contas utilizadas para lavagem de recursos


## Nossa Proposta

O Pix Synapse Fraud Prevention utiliza conceitos de:

✅ Inteligência Artificial

✅ Machine Learning

✅ Monitoramento Transacional

✅ Alertas Preventivos""")

