# Destiny 2 — Servidor Privado

Servidor privado completo para Destiny 2 — Tier 1 (solo/offline) e Tier 2 (multiplayer).

🇧🇷 **Português (Brasil)** | [🇺🇸 English](README.md)

## Arquitetura

```
┌─────────────────────────────────────────────────────────┐
│  Cliente Destiny 2                                       │
│   Chamadas WinHTTP → platform.bungie.net (redirecionado) │
│   Pacotes UDP      → servidor relay                     │
└────────┬───────────────────────────┬────────────────────┘
         │ HTTPS (redirecionado)      │ UDP
         ▼                            ▼
┌─────────────────┐        ┌──────────────────┐
│  Servidor API   │        │  Relay UDP        │
│  api/bungie_api │        │  relay/udp_relay  │
│  Flask + SQLite │        │  Encaminhamento   │
│  porta 8443     │        │  porta 7777       │
└─────────────────┘        └──────────────────┘
         ▲
         │
┌─────────────────┐
│  proxy/winhttp  │ ← injeção no arquivo hosts
│  porta 8080     │   redireciona *.bungie.net → localhost
└─────────────────┘

patch/patch_memory.py ← patcha o processo do jogo em execução:
  - Falsifica sessão de usuário (bypass de autenticação)
  - Desativa kill switches (portões de funcionalidades)
  - Define flag XGameRuntime como pronta
```

## Início Rápido

### Instalar dependências
```bash
pip install -r requirements.txt
```

### Gerar certificados TLS (execute como Administrador)
```bash
python patch/gen_certs.py
```

### Tier 1 — Solo/Offline
```bash
# Terminal 1: Iniciar servidor (como Administrador para o arquivo hosts)
python server.py --tier1

# Terminal 2: Iniciar o jogo, depois aplicar o patch
python patch/patch_memory.py
```

### Tier 2 — Multiplayer Completo
```bash
# Terminal 1: Iniciar todos os servidores
python server.py --tier2

# Terminal 2: Após o jogo carregar
python patch/patch_memory.py
```

## Como Funciona

### Bypass de Autenticação (patch_memory.py)
Baseado na engenharia reversa de `get_active_user_credential()` e `gamcore_get_player_store_context()`:
- Escreve um token falso em `g_user_session + 0x108`
- Define `g_user_session + 0x5c0` (user ID) = 1
- Define `g_user_session + 0x138` (session ID) = 1 (deve corresponder ao user ID)
- Define flag `xgameruntime_ready` = 1 (ignora inicialização do XStore COM)

### Bypass de Kill Switch
O registro de kill switch em `g_killswitch_registry + 0x19808` armazena 512 valores uint32.
`is_killswitch_active(id, threshold=0)` retorna `table[id] <= threshold`.
Definir todos os valores como `5` (> limite padrão 4) desativa TODOS os portões de funcionalidades.

Portões principais:
- `0x12` = verificação de licença
- `0x14` = verificação de assinatura (BAP/XStore)
- `0x1d` = compras no marketplace

### Propriedade de DLC
`dlc_check_offer_entitlement` lê `offer_key.txt` do caminho de entitlement XStore.
Sem necessidade de patch se não precisar de controle de DLC — o servidor de API retorna `versionsOwned: 0xFF`.

### Redirecionamento de Tráfego
`proxy/winhttp_proxy.py` injeta entradas no arquivo hosts:
```
127.0.0.1 platform.bungie.net
127.0.0.1 www.bungie.net
127.0.0.1 oauth.bungie.net
```
Limpe o DNS depois: `ipconfig /flushdns`

### Relay Multiplayer
O relay UDP (`relay/udp_relay.py`) encaminha pacotes de estado do jogo entre jogadores.
Formato do pacote: `[session_id:4][player_id:4][payload:N]`
Sessões são criadas automaticamente e expiram após 5 minutos de inatividade.

## Componentes do Servidor

### Servidor API (`api/bungie_api.py`)
Implementa todos os endpoints que o jogo chama:

| Endpoint | Método | Descrição |
|---|---|---|
| `/SignOn` | GET/POST | Primeira chamada na inicialização — `signon2.gravityshavings.net/SignOn?platform=&build=` |
| `/Platform/App/OAuth/Token/` | POST | Autenticação OAuth — retorna token de acesso |
| `/Platform/User/GetCurrentBungieAccount/` | GET | Conta do usuário atual |
| `/Platform/Destiny2/{type}/Profile/{id}/` | GET | Perfil, personagens, inventário, equipamento |
| `/Platform/Destiny2/Actions/Items/TransferItem/` | POST | Transferir item entre personagem e cofre |
| `/Platform/Destiny2/Actions/Items/EquipItem/` | POST | Equipar item em personagem |
| `/Platform/Destiny2/Actions/Items/EquipItems/` | POST | Equipar múltiplos itens |
| `/Platform/Destiny2/Actions/Items/SetItemLockState/` | POST | Travar/destravar item |
| `/Platform/Destiny2/Actions/Items/PullFromPostmaster/` | POST | Pegar do carteiro |
| `/Platform/Destiny2/Actions/Loadouts/SnapshotLoadout/` | POST | Salvar loadout |
| `/Platform/Destiny2/Actions/Loadouts/EquipLoadout/` | POST | Equipar loadout salvo |
| `/Platform/Destiny2/Manifest/` | GET | Manifest do jogo |
| `/Platform/Destiny2/Milestones/` | GET | Marcos semanais |
| `/Platform/Destiny2/SearchDestinyPlayer/{type}/{name}/` | GET | Buscar jogador |

### Banco de Dados SQLite
Dados persistidos entre sessões:
- **Contas** — membership_id, display_name, tokens
- **Personagens** — class, race, gender, light level
- **Itens** — hash, instance ID, bucket, estado de equipamento, travamento
- **Loadouts** — snapshots de equipamento por slot
- **Recordes** — progresso de triunfos

## Adicionando Conteúdo ao Jogo

### Personagens e Itens
Personagens e itens são armazenados no SQLite (`d2_private.db`).
Edite `api/bungie_api.py` → `init_db()` para adicionar itens padrão.

### Manifest
Coloque um `db/manifest.json` apontando para seu banco de conteúdo.
O jogo baixa o manifest na inicialização — retorne os caminhos que você controla.

### Atividades
Atividades precisam ser carregadas via sistema de pacotes .pkg.
O jogo carrega definições de atividades do manifest — forneça um servidor local
que retorne os hashes de atividade corretos e o engine do jogo trata do resto.

## Limitações Conhecidas

1. **Primeiro login** requer que o jogo alcance a tela de login antes do patch
2. **XStore COM** é ignorado, mas algumas funcionalidades podem ainda exigir o Xbox Gaming Services
3. **Inventário de Vendedor** (`characterVendors`) retorna vazio — implemente se necessário
4. **Progresso de Recordes/Triunfos** não é persistido além da sessão
5. **Atividades** requerem os arquivos de conteúdo reais (arquivos .pkg) para carregar

## Referência de RVAs (do trabalho de ER)

Todos os endereços são RVAs — resolvidos automaticamente para o endereço de carga real.

| Global | RVA | Propósito |
|---|---|---|
| `g_user_session` | `0x1d72f90` | Token falso escrito aqui |
| `g_killswitch_registry` | `0x1fa33c0` | Definir todos os valores como 5 |
| `license_check_suppression` | `0x1fcf410` | Definir como 0 para habilitar verificações |
| `xgameruntime_ready` | `0x2f235a8` | Definir como 1 |
| `g_dlc_state` | `0x1fcf428` | Estado do container DLC |

## Estrutura de Arquivos

```
private_server/
  server.py                  Ponto de entrada master
  requirements.txt           Dependências Python
  README.md                  Documentação (Inglês)
  README_pt-BR.md            Documentação (Português)
  api/
    bungie_api.py            Emulador completo da API REST Bungie
  relay/
    udp_relay.py             Relay UDP para multiplayer
  proxy/
    winhttp_proxy.py         Redirecionamento via arquivo hosts
  patch/
    patch_memory.py          Patcher de memória em tempo de execução
    gen_certs.py             Gerador de certificados TLS
  certs/                     Certificados TLS (gerados por gen_certs.py)
  db/                        Banco de dados e manifest
```
