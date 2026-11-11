# DDoS Attack Simulation Lab: Red Team vs Blue Team

Laboratório **educacional** que roda 100% em `127.0.0.1`. Mostra como excesso de requisições
degrada a disponibilidade de um servidor web e como defesas básicas reduzem o impacto.

## Executar
```bash
pip install -r requirements.txt
python app.py        # abra http://127.0.0.1:5000
```
Clique em **Executar os 3** para rodar Baseline, High Load e Mitigation e comparar os resultados.

## Arquitetura
| Componente | Função |
|---|---|
| Target Server (Flask) | `/api/ping` e `/api/work`; 4 workers e 100 ms por requisição (capacidade ≈ 40 req/s) |
| Red Team Simulator | Threads com `requests`; alvo fixo em localhost; máx. 50 conexões, 30 s e 5000 requisições; botão STOP |
| Blue Team Dashboard | req/s, total, latência, erros 5xx, CPU, RAM, histórico e estado (saudável, degradado ou crítico) |

## Cenários
1. **Baseline**: 2 clientes, sem defesas.
2. **High Load**: 40 conexões simultâneas, sem defesas. A fila dos workers enche e a latência do usuário legítimo sobe.
3. **Mitigation**: mesma carga, com rate limiting (token bucket) e load shedding. O tráfego abusivo recebe 429/503 rápido e o usuário legítimo mantém baixa latência.

Um "usuário legítimo" (probe) roda em paralelo em todos os cenários e é a métrica principal.

## Defesas implementadas
- **Rate limiting** por cliente (token bucket, 15 req/s)
- **Limite de concorrência / load shedding** (rejeita com 503 acima de 8 requisições simultâneas)
- **Timeout de fila** (503 após 2 s esperando worker)

## Limitações (cite no post)
- Os clientes são distinguidos pelo header `X-Client-Id`, uma abstração do laboratório. Em produção, a chave seria IP, token ou fingerprint.
- Atacante e servidor dividem o mesmo processo e CPU, então os números de CPU são indicativos.
- DDoS real é distribuído e volumétrico; em produção a mitigação ocorre em CDN, WAF e borda de rede.

## Ética
Sem botnet, spoofing, evasão ou exploração. Não aponte este código para sistemas de terceiros.
