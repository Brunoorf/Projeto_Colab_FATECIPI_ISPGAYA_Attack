# Projeto de Classificação de Ataques de Rede: Sniffing e Machine Learning (ISPGAYA/FATECIPI)

Este projeto apresenta uma solução de segurança de rede em duas camadas para a detecção e classificação de tentativas de **SQL Injection (SQLi)**. O objetivo foi simular e analisar o tráfego de ataque em um ambiente de teste isolado para desenvolver tanto um sistema de detecção de assinaturas quanto um modelo preditivo baseado em Machine Learning.

**Contexto Acadêmico:** FATEC Ipiranga e ISPGAYA (2025)

---

## 1. Contexto e Geração de Dados (Target Application)

A fase inicial consistiu na simulação e captura de tráfego de ataque contra um alvo conhecido e vulnerável, permitindo a criação do *dataset* de treino.

* [cite_start]**Ambiente Alvo:** Uma aplicação web didática em PHP + SQLite com um formulário de login vulnerável por construção de *query* via concatenação de *input*[cite: 1].
* [cite_start]**Ataques:** Foram registradas e documentadas explorações de *bypass* de autenticação usando *payloads* de SQLi (ex: `' OR '1'='1' -- ` e `admin'-- `)[cite: 1].
* [cite_start]**Evidência:** O servidor emitia um *header* HTTP `Flag: ISPGAYA{SQL_Injection}` ao confirmar a exploração, servindo como rótulo para a análise do tráfego[cite: 1].

**Localização dos Arquivos:** A documentação detalhada dos ataques e o código do site alvo estão em `/target_app`. As imagens de *print* do website (login, login\_SQL, etc.) estão na subpasta de *prints* dentro de `/target_app`.

---

## 2. Camada 1: Sistema de Detecção Baseado em Regras (`sniffer_rules`)

A primeira solução de segurança implementa um Sniffer de pacotes para detecção de ameaças conhecidas em tempo real, utilizando assinaturas.

* **Script Principal:** `SOC_COIL.py`
* **Tecnologia:** Utiliza a biblioteca `Scapy` para monitoramento de pacotes na interface de rede.
* **Mecanismo de Detecção:** Classificação do tráfego através de **Expressões Regulares (RegEx)** no *payload* do pacote para identificar padrões de SQLi (`UNION SELECT`, `OR 1=1`) e a *flag* de sucesso do ataque (`ISPGAYA\{([^}]*)\}`).

---

## 3. Camada 2: Classificação Preditiva com Machine Learning (`ml_model`)

Para aumentar a capacidade de detecção de padrões complexos e novas variações de ataque, foi desenvolvido e otimizado um modelo de Machine Learning.

### 3.1. Análise Exploratória e Engenharia de Features

O tráfego capturado foi processado e transformado em um conjunto de **11 *features*** para treinamento:

* **Features Derivadas:** Comprimento do pacote (`Length`), Porta de Origem (`Source_Port`), Porta de Destino (`Destination_Port`), e indicadores binários para protocolos (TCP, UDP, Outro) e heurísticas de *payload* (ex: `Has_Quote`, `Has_Union`).
* **Processamento:** Aplicado **Feature Scaling** (Padronização) nas *features* contínuas para otimizar o desempenho do modelo.

### 3.2. Modelagem e Resultados Otimizados

* **Modelo:** **Random Forest Classifier**.
* **Balanceamento:** Aplicado o método **SMOTE** para balancear as classes de treino, mitigando o desbalanceamento.
* **Otimização:** Utilizado **RandomizedSearchCV** com validação cruzada para otimizar o modelo, utilizando o **F1-Score** como métrica primária (atingindo 0.9747 na validação cruzada).

| Métrica | Precision | Recall | F1-Score | Support (Total) |
| :--- | :--- | :--- | :--- | :--- |
| **Tráfego Normal (Label 0)** | 0.98 | 0.97 | 0.97 | 15,637 |
| **Tráfego Anômalo (Label 1)** | 0.97 | 0.98 | 0.98 | 17,776 |
| **Acurácia Geral** | - | - | - | **0.97** |

O modelo final atingiu uma **Acurácia de 0.97** no conjunto de teste, demonstrando alta eficácia na classificação do tráfego de rede.

**Visualização do Modelo:**

**Localização dos Arquivos:**
* Notebook de EDA/Treinamento: `ml_model/GCOLAB_ISP_Gaya_FATECIPI.ipynb`
* Modelo Serializado: `ml_model/best_random_forest_final.joblib`

---

## ⚙️ Configuração do Repositório

### Estrutura de Pastas
FATECIPI-ISPGAYA-PROJETO/ ├─ README.md ├─ requirements.txt ├─ .gitignore ├─ /target_app/ # Aplicação vulnerável e documentação do ataque ├─ /sniffer_rules/ # Código do Sniffer (detecção por Regras) ├─ /ml_model/ # Notebook, modelo treinado e gráficos de avaliação └─ /data/ # Amostras do dataset (vazio)

### Tecnologias

O projeto utiliza Python 3.12 e as bibliotecas listadas em `requirements.txt`.

### Requisitos

Para replicar o ambiente e o treinamento do modelo, instale as dependências:

```bash
pip install -r requirements.txt