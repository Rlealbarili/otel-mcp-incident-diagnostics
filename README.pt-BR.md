# ⚡ Plataforma CIRES-R de Observabilidade da Saúde de Sistemas de Software & Diagnósticos Automatizados de Incidentes via IA

[![tests](https://github.com/Rlealbarili/otel-mcp-incident-diagnostics/actions/workflows/tests.yml/badge.svg)](https://github.com/Rlealbarili/otel-mcp-incident-diagnostics/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![OpenTelemetry](https://img.shields.io/badge/OpenTelemetry-v1.25.0-orange.svg)](https://opentelemetry.io/)
[![Grafana LGTM](https://img.shields.io/badge/Grafana-LGTM%20Stack-F46800.svg)](https://grafana.com/)
[![NIST CSF 2.0](https://img.shields.io/badge/NIST%20CSF-2.0%20Conforme-00e676.svg)](https://www.nist.gov/cyberframework)
[![CIRES-R](https://img.shields.io/badge/Doutrina-CIRES--R%20Robustez-7f00ff.svg)](#doutrina-de-engenharia-cires-r)
[![Licença](https://img.shields.io/badge/Licen%C3%A7a-Apache%202.0-blue.svg)](LICENSE)

**Português (Brasil)** | [**English**](README.md)

Plataforma distribuída de observabilidade e ingestão de telemetria da **saúde de sistemas computacionais e softwares**, focada em segurança de credenciais e diagnóstico autônomo de incidentes. Desenvolvida com **OpenTelemetry (OTel)**, **Grafana LGTM Stack** (Loki, Tempo, Mimir/Prometheus) e **Model Context Protocol (MCP)**, alinhada ao framework **NIST CSF 2.0**.

---

## 🌟 Resumo Executivo & Destaques da Arquitetura

Sistemas modernos de software exigem **alta vazão de observabilidade da saúde da infraestrutura e microsserviços** combinada com garantias absolutas de **zero vazamento de credenciais, chaves de API ou dados sensíveis**. A plataforma oferece:

- **Redação de Segredos Fail-Closed**: Intercepta Chaves de API (`sk-`), Bearer Tokens, Senhas, Strings de Conexão com Banco de Dados, JWTs e Chaves Privadas na fronteira do OpenTelemetry Collector. Em caso de falha de parser ou estouro de memória, o payload é automaticamente substituído por `[REDACTED_FAIL_CLOSED]`.
- **Fila em Disco Resiliente Dual-Tier**: Opera uma fila de envio persistente em disco (`file_storage`, 5.000 lotes) pareada com `memory_limiter` (80% limite rígido / 20% limite de pico) e política de retry com *exponential backoff* (5s a 60s) para garantir perda zero de telemetria em quedas de infraestrutura.
- **Root Cause Analysis (RCA) Autônomo com IA para Softwares**: Correlaciona métricas (Mimir) → grafos de traces (Tempo) → stack traces de erro (Loki) via MCP (`mcp-grafana`) para gerar relatórios de mitigação de incidentes de software mapeados para as 6 funções do NIST CSF 2.0.
- **Dashboard Interativo Glassmorphic de Saúde de Sistemas**: Interface web em `/ui` para monitoramento da saúde computacional em tempo real (CPU, RAM, Conexões, Latência), simulação de incidentes de software (picos de latência, timeouts de serviço, exaustão de pool de banco) e visualização de relatórios de RCA.

---

## 📐 Arquitetura do Sistema

```
+-----------------------------------------------------------------------------------+
|                     CAMADA DE SISTEMAS COMPUTACIONAIS & APLICAÇÕES                |
|  - FastAPIRoutes (health_routes.py, patient_routes.py)                            |
|  - Middleware (telemetry.py - OTel SDK, sanitize.py - Sanitização de Segredos)    |
|  - Workers (health_ingestion.py, fault_simulator.py, rca_engine.py)               |
+-----------------------------------------------------------------------------------+
                                         |
                                         | OTLP / gRPC (Porta 4317)
                                         | Propagação de TraceContext (traceparent)
                                         v
+-----------------------------------------------------------------------------------+
|                        PIPELINE DO OPENTELEMETRY COLLECTOR                        |
|  [Receivers]    : OTLP gRPC (4317), OTLP HTTP (4318)                              |
|  [Processors]   : memory_limiter -> transform/redactor (fail-closed) -> batch     |
|  [Extensions]   : file_storage (Fila persistente em disco)                        |
|  [Exporters]    : otlp/loki, otlp/tempo, prometheusremotewrite                    |
+-----------------------------------------------------------------------------------+
                                         |
                +------------------------+------------------------+
                | (Logs)                 | (Traces)               | (Métricas)
                v                        v                        v
        +---------------+        +---------------+        +---------------+
        |     Loki      |        |     Tempo     |        | Mimir/Prometh.|
        | (LogQL Engine)|        | (Trace Engine)|        | (PromQL Engine|
        +---------------+        +---------------+        +---------------+
                                         |
                                         v (Repositório de Telemetria Unificado)
+-----------------------------------------------------------------------------------+
|                            CAMADA MCP & AGENTE DIAGNÓSTICO                        |
|                                                                                   |
|  +---------------------+  +---------------------+  +---------------------------+  |
|  |     mcp-grafana     |  | chrome-devtools-mcp |  |     cires_rag_search      |  |
|  | (API de Consultas   |  | (Validação Visual   |  | (Mapeamento NIST CSF 2.0, |  |
|  |  Métricas, Logs, Tr) |  |  DOM, Network)      |  |  Playbooks RCA, Specs)    |  |
|  +---------------------+  +---------------------+  +---------------------------+  |
|                                   \       |       /                               |
|                                    v      v      v                                |
|                        +-------------------------------------+                    |
|                        |   AGENTE DIAGNÓSTICO AUTÔNOMO DE    |                    |
|                        |        INCIDENTES DE SOFTWARE       |                    |
|                        |  - Gatilho de Anomalias de Sistema  |                    |
|                        |  - Correlação Métrica->Trace->Log   |                    |
|                        |  - RCA & Mitigação NIST CSF 2.0     |                    |
|                        +-------------------------------------+                    |
+-----------------------------------------------------------------------------------+
```

---

## 🏛️ Matriz de Mapeamento NIST CSF 2.0

| Função NIST | Foco Principal | Implementação no Sistema |
|---|---|---|
| **Govern (GV)** | Governança e Limites | Topologia padronizada (`backend/`, `scripts/`, `tests/`), mascaramento obrigatório de segredos, especificações versionadas em `openspec/`. |
| **Identify (ID)** | Classificação de Riscos de Segredos | Tagger de telemetria e mapeamento de vetores de risco de credenciais e chaves nos traces e logs. |
| **Protect (PR)** | Zero Vazamento de Segredos | Redator Regex Fail-Closed no OTel Collector (`scripts/otel-collector.yaml`) + Memory Limiter. |
| **Detect (DE)** | Detecção de Anomalias de Sistema | Correlação entre exemplares de métricas → grafos de trace Tempo → stack traces Loki. |
| **Respond (RS)** | RCA Autônomo & Playbooks de Software | Agente MCP consultando a telemetria e gerando relatórios de mitigação para falhas de software. |
| **Recover (RC)** | Resiliência & Fila | Fila persistente `file_storage` em disco (5.000 lotes) mantendo a telemetria protegida durante indisponibilidades. |

---

## 🛡️ Doutrina de Engenharia CIRES-R

O projeto opera sob a **Doutrina CIRES-R** com foco principal no **R (Robustez)**:

- **C — Clareza**: Contratos de API autodocumentados e separação estrita de escopos (`backend/routes`, `backend/workers`, `tests/`, `openspec/`).
- **I — Inteligência**: Extração otimizada de exemplares de métricas e propagação de contexto sem redundâncias.
- **R — Robustez (Foco Principal)**: Mecanismos de segurança *fail-closed*, filas dual-tier, cooldown de 60s contra tempestades de alertas.
- **E — Elegância**: Interface gráfica Glassmorphic, código Python tipado e logs estruturados em JSON.
- **S — Segurança**: Git exclusivamente via SSH (chaves de autenticação), alinhamento com NIST CSF 2.0 e isolamento de escopos.

---

## 🚀 Guia de Inicialização Rápida

### Pré-requisitos
- Python 3.12+
- Docker & Docker Compose
- Git com autenticação SSH configurada

### 1. Clonar e Configurar o Repositório
```bash
git clone https://github.com/Rlealbarili/otel-mcp-incident-diagnostics.git
cd otel-mcp-incident-diagnostics
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

### 2. Iniciar o Backend & Dashboard Local
```bash
python3 -m backend.main
```
Acesse no seu navegador: `http://localhost:8000/ui` para utilizar o **Dashboard de Saúde de Sistemas**.

---

## 🧪 Execução da Suíte de Testes

Execute a suíte de testes automatizados:
```bash
python3 -m pytest tests/ -v
```

---

## 📄 Licença & Autor

**Autor**: Rafael Henrique Leal Barili ([@Rlealbarili](https://github.com/Rlealbarili))  
**Licença**: [Apache License 2.0](LICENSE)
