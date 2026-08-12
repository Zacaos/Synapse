
import streamlit as st
import pandas as pd
import numpy as np
import altair as alt
from datetime import datetime, timedelta
import random

st.set_page_config(page_title='Synapse Platform', page_icon='🛡️', layout='wide')

if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False

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
      'lon':np.random.uniform(-73,-34,n),
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


def analisar_comportamento_cpf(cpf_query, df):
    """Analisa o comportamento de um CPF específico"""
    cpf_data = df[df['cpf'] == cpf_query]
    
    if len(cpf_data) == 0:
        return None
    
    # Análises gerais
    num_transacoes = len(cpf_data)
    valor_total = cpf_data['amount'].sum()
    valor_medio = cpf_data['amount'].mean()
    valor_max = cpf_data['amount'].max()
    valor_min = cpf_data['amount'].min()
    
    # Análise de destinos
    destinos = cpf_data['destination'].value_counts()
    pct_apostas = (len(cpf_data[cpf_data['destination'] == 'Casa de Apostas']) / num_transacoes * 100) if num_transacoes > 0 else 0
    pct_ecommerce = (len(cpf_data[cpf_data['destination'] == 'E-commerce']) / num_transacoes * 100) if num_transacoes > 0 else 0
    
    # Análise de localização (Impossible Travel)
    locs = cpf_data[['lat', 'lon', 'timestamp']].sort_values('timestamp')
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
    score_medio = cpf_data['score'].mean()
    risco = decision(score_medio)
    
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
        'dados_detalhados': cpf_data
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
    st.title('🔍 Behavior Analytics')
    
    tab1, tab2 = st.tabs(['Análise Global', 'Consulta Individual por CPF'])
    
    with tab1:
        a,b,c=st.columns(3)
        a.metric('Clusters',120)
        b.metric('Anomalias',82)
        c.metric('MED',19)
        st.map(DF[['lat','lon']].head(1000),latitude='lat',longitude='lon')
    
    with tab2:
        st.subheader('📋 Análise Comportamental Individual')
        
        cpf_input = st.text_input('Digite o CPF para análise', placeholder='Ex: 10000000000')
        
        if cpf_input:
            resultado = analisar_comportamento_cpf(cpf_input, DF)
            
            if resultado is None:
                st.warning('❌ CPF não encontrado na base de dados')
            else:
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
