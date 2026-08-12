
import streamlit as st
import pandas as pd
import numpy as np
import altair as alt
from datetime import datetime, timedelta
import random

st.set_page_config(page_title='Synapse Platform', page_icon='🛡️', layout='wide')

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

# Coordenadas das regiões do Brasil
REGIOES_BRASIL = {
    'Sudeste': {'lat': -23.5, 'lon': -46.6, 'bounds': [(-28, -52), (-19, -41)]},
    'Nordeste': {'lat': -5.5, 'lon': -39.0, 'bounds': [(-1, -35), (-18, -48)]},
    'Norte': {'lat': -3.1, 'lon': -60.0, 'bounds': [(2, -49), (-17, -74)]},
    'Centro-Oeste': {'lat': -15.8, 'lon': -56.0, 'bounds': [(-7, -49), (-23, -62)]},
    'Sul': {'lat': -28.5, 'lon': -51.5, 'bounds': [(-22, -49), (-34, -56)]}
}

@st.cache_data
def gerar_dados():
    random.seed(42)
    np.random.seed(42)
    n=3000
    cats=['Conta OK','Mule Account','Application Fraud','Scammer Account']
    
    # Distribuir pontos sobre as regiões do Brasil
    lats = []
    lons = []
    for i in range(n):
        regiao = np.random.choice(list(REGIOES_BRASIL.keys()), p=[0.35, 0.30, 0.15, 0.12, 0.08])
        bounds = REGIOES_BRASIL[regiao]['bounds']
        lat = np.random.uniform(bounds[1][0], bounds[0][0])
        lon = np.random.uniform(bounds[0][1], bounds[1][1])
        lats.append(lat)
        lons.append(lon)
    
    df=pd.DataFrame({
      'transaction_id':[f'PIX{i}' for i in range(n)],
      'timestamp':[datetime.now()-timedelta(hours=random.randint(0,720)) for _ in range(n)],
      'pix_key':[f'cliente{i}@mail.com' for i in range(n)],
      'cpf':[str(10000000000+i) for i in range(n)],
      'documento':[f'RG{10000000+i}' for i in range(n)],
      'telefone':[f'11{90000000+i}' for i in range(n)],
      'email':[f'usuario{i}@email.com' for i in range(n)],
      'amount':np.round(np.random.lognormal(6.5,1.1,n),2),
      'score':np.random.randint(1,100,n),
      'lat':lats,
      'lon':lons,
      'destination':np.random.choice(['E-commerce','Pessoa Física','Casa de Apostas','Serviços'],n,p=[0.5,0.3,0.15,0.05])
    })
    df['categoria']=np.random.choice(cats,n,p=[0.9,0.04,0.03,0.03])
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


def analisar_por_regiao(df):
    """Analisa riscos por região"""
    df['regiao'] = df.apply(lambda row: obter_regiao(row['lat'], row['lon']), axis=1)
    
    analise_regoes = {}
    for regiao in REGIOES_BRASIL.keys():
        df_regiao = df[df['regiao'] == regiao]
        if len(df_regiao) > 0:
            score_medio = df_regiao['score'].mean()
            num_transacoes = len(df_regiao)
            valor_total = df_regiao['amount'].sum()
            pct_apostas = (len(df_regiao[df_regiao['destination'] == 'Casa de Apostas']) / num_transacoes * 100)
            pct_fraude = (len(df_regiao[df_regiao['categoria'] != 'Conta OK']) / num_transacoes * 100)
            
            analise_regoes[regiao] = {
                'score_medio': score_medio,
                'num_transacoes': num_transacoes,
                'valor_total': valor_total,
                'pct_apostas': pct_apostas,
                'pct_fraude': pct_fraude,
                'lat': REGIOES_BRASIL[regiao]['lat'],
                'lon': REGIOES_BRASIL[regiao]['lon']
            }
    
    return analise_regoes


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

DF=gerar_dados()

st.sidebar.title('🛡️Synapse Pix Antifraude')
st.sidebar.write(f"Usuário: {st.session_state.user}")
st.sidebar.write(f"Perfil: {st.session_state.perfil}")
menu=st.sidebar.radio('Módulos',[
'Synapse Dashboard','Consulta Chave Pix','Consulta Contas',
'Validação de Scores','Behavior Analytics','Transações Monitoradas','Alertas'])

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

elif menu=='Consulta Chave Pix':
    st.title('Consulta de Score por Chave Pix')
    chave=st.text_input('Digite a chave Pix')
    if chave:
        st.metric('Score',np.random.randint(60,99))
        st.metric('Classificação','Alto Risco')
        st.metric('TPV','R$ 458.000')
        st.dataframe(DF[['pix_key','amount','score','categoria']].head(20),use_container_width=True)

elif menu=='Consulta Contas':
    st.title('Consulta de Contas')
    conta=st.text_input('CPF/CNPJ/Conta')
    if conta:
        t1,t2,t3,t4=st.tabs(['Resumo','Dispositivos','Pix','Behavior'])
        t1.write('Resumo da conta')
        t2.write('Dispositivos vinculados')
        t3.dataframe(DF[['pix_key','score']].head(10))
        t4.write('Indicadores comportamentais')

elif menu=='Validação de Scores':

# --------------------------------------------------
# PROCESSAMENTO DA BASE DE SCORES
# --------------------------------------------------

    st.title(
        "📦 Cálculo do Score em lote"
    )

    st.info(
        "**📋 Instruções de Upload:**\n\n"
        "Seu arquivo CSV deve conter as seguintes colunas:\n\n"
        "- **transaction_id** (obrigatório): Identificador único da transação\n"
        "- **pix_key** (obrigatório): Chave Pix da transação\n"
        "- **cpf** (obrigatório): CPF do cliente\n"
        "- **amount** (obrigatório): Valor da transação (numérico)\n"
        "- **timestamp** (opcional): Data/hora da transação\n"
        "- **lat** (opcional): Latitude para análise geográfica\n"
        "- **lon** (opcional): Longitude para análise geográfica\n\n"
        "O sistema gerará automaticamente a coluna **score** (1-99) e **decision** (Alto/Médio/Baixo Risco)"
    )

    arquivo = st.file_uploader(
        "Upload CSV",
        type=["csv"]
    )

    if arquivo:

        massa = pd.read_csv(
            arquivo
        )

        st.write(
            "Prévia da Massa"
        )

        st.dataframe(
            massa.head()
        )

        if st.button(
            "Processar Massa"
        ):

            massa["score"] = np.random.randint(
                1,
                99,
                len(massa)
            )

            massa["decision"] = massa[
                "score"
            ].apply(
                decision
            )

            st.success(
                "Processamento concluído"
            )

            st.dataframe(
                massa.head(100),
                use_container_width=True
            )

            csv = massa.to_csv(
                index=False
            )

            st.download_button(
                "Download Resultado",
                csv,
                "pix_scores.csv"
            )




elif menu=='Behavior Analytics':
    st.title('🔍 Behavior Analytics - Brasil')
    
    tab1, tab2 = st.tabs(['Análise Regional', 'Consulta Individual'])
    
    with tab1:
        st.subheader('🗺️ Mapa de Riscos por Região')
        
        # Análise por região
        analise_regoes = analisar_por_regiao(DF)
        
        # Criar visualização do risco por região
        col1, col2 = st.columns(2)
        
        with col1:
            # Mapa com pontos de risco
            mapa_data = DF.copy()
            # Colorir por risco
            mapa_data['color'] = mapa_data['score'].apply(
                lambda x: '🔴 Alto Risco' if x >= 80 else ('🟡 Médio Risco' if x >= 50 else '🟢 Baixo Risco')
            )
            st.map(mapa_data[['lat','lon']].head(1000), latitude='lat', longitude='lon', zoom=3)
        
        with col2:
            st.subheader('📊 Indicadores por Região')
            
            # Criando cards para cada região
            for regiao, dados in sorted(analise_regoes.items(), key=lambda x: x[1]['score_medio'], reverse=True):
                risco_texto = decision(dados['score_medio'])
                if risco_texto == 'Alto Risco':
                    st.error(f"🔴 **{regiao.upper()}** - {risco_texto}")
                elif risco_texto == 'Médio Risco':
                    st.warning(f"🟡 **{regiao.upper()}** - {risco_texto}")
                else:
                    st.success(f"🟢 **{regiao.upper()}** - {risco_texto}")
                
                col_a, col_b, col_c, col_d = st.columns(4)
                col_a.metric('Score Médio', f"{dados['score_medio']:.1f}")
                col_b.metric('Transações', dados['num_transacoes'])
                col_c.metric('Apostas', f"{dados['pct_apostas']:.1f}%")
                col_d.metric('Fraude', f"{dados['pct_fraude']:.1f}%")
                st.divider()
        
        st.subheader('🚩 Insights e Red Flags por Região')
        
        # Insights para Sudeste e Nordeste
        col_sudeste, col_nordeste = st.columns(2)
        
        with col_sudeste:
            if 'Sudeste' in analise_regoes:
                dados_sudeste = analise_regoes['Sudeste']
                st.subheader('🔴 Sudeste (Maior Risco)')
                
                red_flags = []
                if dados_sudeste['score_medio'] > 70:
                    red_flags.append(f"⚠️ Score muito elevado: {dados_sudeste['score_medio']:.1f}")
                if dados_sudeste['pct_apostas'] > 25:
                    red_flags.append(f"⚠️ Alto uso de casas de apostas: {dados_sudeste['pct_apostas']:.1f}%")
                if dados_sudeste['pct_fraude'] > 15:
                    red_flags.append(f"⚠️ Taxa de fraude acima do normal: {dados_sudeste['pct_fraude']:.1f}%")
                
                if red_flags:
                    for flag in red_flags:
                        st.write(flag)
                else:
                    st.success("✅ Nenhuma bandeira vermelha detectada")
                
                st.info(f"💡 **Insight**: A região Sudeste concentra o maior volume de transações ({dados_sudeste['num_transacoes']}) com score médio de {dados_sudeste['score_medio']:.1f}")
        
        with col_nordeste:
            if 'Nordeste' in analise_regoes:
                dados_nordeste = analise_regoes['Nordeste']
                st.subheader('🟡 Nordeste (Risco Moderado)')
                
                red_flags = []
                if dados_nordeste['score_medio'] > 60:
                    red_flags.append(f"⚠️ Score elevado: {dados_nordeste['score_medio']:.1f}")
                if dados_nordeste['pct_apostas'] > 20:
                    red_flags.append(f"⚠️ Atividade em casas de apostas: {dados_nordeste['pct_apostas']:.1f}%")
                if dados_nordeste['pct_fraude'] > 10:
                    red_flags.append(f"⚠️ Taxa de fraude: {dados_nordeste['pct_fraude']:.1f}%")
                
                if red_flags:
                    for flag in red_flags:
                        st.write(flag)
                else:
                    st.success("✅ Nenhuma bandeira vermelha detectada")
                
                st.info(f"💡 **Insight**: A região Nordeste apresenta {dados_nordeste['num_transacoes']} transações com padrão de risco moderado")
    
    with tab2:
        st.subheader('📋 Análise Comportamental Individual')
        
        # Seleção do tipo de busca
        tipo_busca = st.radio(
            '🔍 Selecione o tipo de busca:',
            ['CPF', 'Chave Pix', 'Documento', 'Telefone', 'E-mail', 'Aleatória', 'E2E (Todas as informações)'],
            horizontal=True
        )
        
        resultado = None
        
        if tipo_busca == 'CPF':
            cpf_input = st.text_input('Digite o CPF', placeholder='Ex: 10000000000')
            if cpf_input:
                resultado = analisar_comportamento(buscar_por_campo(cpf_input, 'cpf', DF), DF, 'CPF')
        
        elif tipo_busca == 'Chave Pix':
            pix_input = st.text_input('Digite a Chave Pix', placeholder='Ex: cliente0@mail.com')
            if pix_input:
                resultado = analisar_comportamento(buscar_por_campo(pix_input, 'pix_key', DF), DF, 'Chave Pix')
        
        elif tipo_busca == 'Documento':
            doc_input = st.text_input('Digite o Documento (RG)', placeholder='Ex: RG10000000')
            if doc_input:
                resultado = analisar_comportamento(buscar_por_campo(doc_input, 'documento', DF), DF, 'Documento')
        
        elif tipo_busca == 'Telefone':
            tel_input = st.text_input('Digite o Telefone', placeholder='Ex: 11900000000')
            if tel_input:
                resultado = analisar_comportamento(buscar_por_campo(tel_input, 'telefone', DF), DF, 'Telefone')
        
        elif tipo_busca == 'E-mail':
            email_input = st.text_input('Digite o E-mail', placeholder='Ex: usuario0@email.com')
            if email_input:
                resultado = analisar_comportamento(buscar_por_campo(email_input, 'email', DF), DF, 'E-mail')
        
        elif tipo_busca == 'Aleatória':
            if st.button('🎲 Gerar Consulta Aleatória'):
                indice_aleatorio = np.random.randint(0, len(DF))
                registro_aleatorio = DF.iloc[indice_aleatorio]
                cpf_aleatorio = registro_aleatorio['cpf']
                resultado = analisar_comportamento(buscar_por_campo(cpf_aleatorio, 'cpf', DF), DF, 'CPF (Aleatória)')
                st.info(f"📊 CPF selecionado aleatoriamente: **{cpf_aleatorio}**")
        
        elif tipo_busca == 'E2E (Todas as informações)':
            st.info('🔗 **Busca End-to-End**: Insira qualquer informação do cliente e o sistema buscará em todos os campos')
            e2e_input = st.text_input('Digite qualquer identificador (CPF, Chave Pix, Email, Telefone, etc)', placeholder='Ex: usuario0@email.com')
            if e2e_input:
                # Busca em múltiplos campos
                resultado_cpf = buscar_por_campo(e2e_input, 'cpf', DF)
                resultado_pix = buscar_por_campo(e2e_input, 'pix_key', DF) if resultado_cpf is None else None
                resultado_doc = buscar_por_campo(e2e_input, 'documento', DF) if resultado_pix is None else None
                resultado_tel = buscar_por_campo(e2e_input, 'telefone', DF) if resultado_doc is None else None
                resultado_email = buscar_por_campo(e2e_input, 'email', DF) if resultado_tel is None else None
                
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
                    st.warning(f'❌ Nenhuma correspondência encontrada para: {e2e_input}')
        
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
        
        elif resultado is None and tipo_busca != 'Aleatória' and tipo_busca != 'E2E (Todas as informações)':
            pass
        elif tipo_busca not in ['Aleatória', 'E2E (Todas as informações)']:
            st.warning('❌ Nenhum resultado encontrado. Verifique o identificador e tente novamente.')

elif menu=='Transações Monitoradas':
    st.title('Transações Monitoradas')
    score=st.slider('Score mínimo',0,100,50)
    st.dataframe(DF[DF.score>=score],use_container_width=True)

elif menu=='Alertas':
    st.title('Alertas Antifraude')
    alertas=DF[DF.categoria!='Conta OK']
    c1,c2=st.columns(2)
    c1.metric('Total Alertas',len(alertas))
    c2.metric('Volume Suspeito',f"R$ {alertas.amount.sum():,.0f}")
    h=alertas.copy(); h['hora']=pd.to_datetime(h.timestamp).dt.hour
    st.bar_chart(h.groupby('hora').size())
    st.dataframe(alertas.head(200),use_container_width=True)
