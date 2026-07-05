
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
    st.title('Validação de Scores')
    pesos=pd.DataFrame({'Feature':['DICT','Behavior','Velocity','Device','GeoRisk'],'Peso':[30,25,20,15,10]})
    st.dataframe(pesos,use_container_width=True)
    st.bar_chart(pesos.set_index('Feature'))

elif menu=='Behavior Analytics':
    st.title('Behavior Analytics')
    a,b,c=st.columns(3)
    a.metric('Clusters',120)
    b.metric('Anomalias',82)
    c.metric('MED',19)
    st.map(DF[['lat','lon']].head(1000),latitude='lat',longitude='lon')

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
