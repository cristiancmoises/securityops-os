# Security Ops OS

Security Ops OS é uma distribuição GNU/Linux completa, inicializável e
instalável. GNU Guix é a base declarativa usada para pacotes, configuração do
sistema, atualizações atômicas e reversão; ele não é apresentado como o nome do
produto. As superfícies de identidade mostram:

```text
uname -s  -> Linux
uname -o  -> Security Ops OS
```

`/etc/os-release`, `/etc/issue`, GRUB, o instalador e o identificador de build
usam a mesma versão. Esta configuração constrói `1.14.0` / `r13` com Linux
`7.3.4-SecurityOps`.

## Inicialização e acesso ao modo live

v1.14.0 (r13), 13/11/2026: esta versão compila o kernel customizado Linux
7.3.4-SecurityOps (receita de hardening + performance) a partir da fonte do
cdn.kernel.org, com o SHA-256 autenticado pelo desenvolvedor registrado em
`securityops/settings.json`. O grafo de canais é o conjunto completo do
mantenedor em commits exatos: guix, nonguix, radix, rosenthal, small-guix,
securityops, gocix e sops-guix (`channels.guix`). Os overrides selecionam as
versões mais novas disponíveis: Thunar 4.20.10, Heroic 2.22.1, Steam 1.0.0.87,
Tor Browser 16.0.1, guixvis 0.8.0, Security Ops Installer 2 0.1.0 e Security
Ops Guix Center 0.2.0. A imagem também embarca a suíte criativa ArtCraft a
partir dos binários Linux oficiais: PhotoCraft 0.9.0, VectorCraft 0.10.0,
FilmCraft 0.7.2, LightCraft 0.8.0, PdfCraft 0.8.0, EffectCraft 0.10.0,
DesignCraft 0.8.0, FigCraft 0.6.0, WordCraft 0.7.0, SoundCraft 0.5.0,
DeckCraft 0.7.0, CADCraft 0.7.0 e GridCraft 0.7.0. A ISO embarca o fluxo de
instalação rápida (instalador guiado + Installer 2 + Guix Center) e roda ao
vivo com os mesmos alvos de velocidade/hardening da série v1.13.0. Confira
`GET_THE_ISO.md` para os checksums do artefato e os links de download direto
e torrent.

Sintaxe da versão do kernel, 21/10/2026: CLI e adaptador Guile aceitam
literalmente versões iniciais `X.Y` e correções `X.Y.Z`, sem acrescentar ou
remover `.0`. A versão do sistema continua exigindo `X.Y.Z` ou `X.Y.Z-rc.N`.
Registro histórico de 21/10/2026: a prévia da CLI para Linux 7.3 chegou
ao requisito de download, mas ainda faltava Guix no CT128. Aquela tentativa
manteve o pin 7.2.11 da época e os canais inalterados.
Testes do parser não autenticam a fonte nem comprovam compilação, boot ou ISO.

Atualização histórica da fonte candidata em 17/10/2026: Linux 7.2.11 foi fixado pelo
`./securityopsctl kernel set 7.2.11`, após prévia real. SHA-256 e nix-base32
Guix do arquivo oficial coincidem; a assinatura do desenvolvedor sobre o tar
descomprimido foi verificada novamente em chaveiro público isolado. Canais,
pacotes e hardening não mudaram. Isso não é compilação nem boot do kernel.
O resultado dos 29 valores abaixo pertence ao 7.2.8, não qualifica o 7.2.11;
derivação fixada, configuração/compilação, boot e ISO ainda precisam de validação.

Atualização histórica da fonte em 26/09/2026: Linux 7.2.8 foi fixado pelo
`./securityopsctl kernel set 7.2.8`, com hashes Guix/SHA-256 medidos localmente
e assinatura do desenvolvedor verificada via kernel.org. Uma derivação Guix
executou a configuração real da receita até o verificador estrito: passaram
os 29 valores exigidos, incluindo HZ=1000, IOMMU estrito e VFIO sem IOMMU
desativado. Receita de hardening e pins dos canais não mudaram. Esse diagnóstico
não compila nem inicializa o kernel, não comprova correção dos erros anteriores
do modo live e não fornece uma ISO reconstruída.

Reparo de empacotamento de 26/09/2026: as receitas isoladas do Guix Center e do
Installer 2 declaram Bash, Python e os caminhos Qt/GTK. Os comandos de construção
e de verificação dos pacotes estão no README em inglês. O teste
`tests/check_gui_package_artifacts.py` verifica lançadores, preservação dos
arquivos-fonte e importações sem abrir aplicativos. Isso não atualiza a ISO nem
valida boot, instalação ou autenticação do grafo de canais. O Installer 2 ainda
é um planejador, com aplicação destrutiva bloqueada. A reconciliação das fontes
e os testes live/instalação continuam pendentes; os metadados históricos acima
não identificam os novos pacotes construídos.

Seleção de aplicativos (27/09/2026, atualizada em 13/11/2026): os overrides
canônicos agora selecionam Thunar 4.20.10, Guix Center 0.2.0, Installer 2
0.1.0, Heroic 2.22.1 do Nonguix, Steam 1.0.0.87 do canal SecurityOps fixado,
Tor Browser 16.0.1 do canal SecurityOps fixado e guixvis 0.8.0 (antigo
pacvis). Consulte-os com
`./securityopsctl package changes`. Eles alimentam tanto o live quanto os
sistemas gerados pelo instalador; os testes carregam as listas reais de pacotes
e verificam identidade do provedor, unicidade e saída padrão em cada desktop
suportado. Isso é integração de fontes, não execução gráfica nem uma nova ISO.
O Installer 2 continua apenas como planejador, com instalação bloqueada.
As pendências de procedência do Store, boot e instalação permanecem abertas.
A versão do Steam identifica seu lançador inicial, não o cliente que se
autoatualiza. Não houve abertura dos clientes, login, aceite de licenças ou
teste de jogos. A origem HTTP do Steam (com hash fixado) e a validação de
runpath desativada na receita do Heroic seguem como pendências de revisão
para release; consulte SECURITY.md.
O override do Tor também inclui o navegador nos sistemas gerados pelo
instalador, onde antes faltava. `torbrowser@16.0.1` resolve para uma única
receita no grafo fixado; os testes obrigatórios exigem o objeto do pacote e
rejeitam troca de provedor. Isso não comprova abertura do navegador, anonimato
ou segurança; novos pins exigem nova validação.

A receita GPL local do guixvis importa a receita revisada do canal SecurityOps
no commit `017b9e3aa09bbafca341dfba7c91ca96211e8020`, com URLs HTTPS imutáveis
e hashes medidos. O pin do canal avança para
`34a0099058eada895d92069f36feb2267ebfa203` na imagem r13 atualizada, enquanto
as origens do guixvis permanecem no commit revisado. Preserva build/testes
Cargo frozen/offline, suporte web e os inputs Rust/Cargo do Guix fixado. Os jobs de
compilação Cargo seguem a seleção de cores do Guix (um job sem build paralelo);
isso não limita toda a memória ou todas as threads. Use `guixvis`
para a interface de terminal ou invoque explicitamente `guixvis web` para a
interface web em loopback; nenhum serviço inicia automaticamente. A receita
canônica foi compilada uma vez no grafo fixado: 121 testes Rust passaram,
dois testes live/cache do upstream ficaram ignorados; `--help` e `--version`
passaram. Não comprova reprodutibilidade, validação completa da interface/indexador
ou qualificação da ISO; a compilação diagnóstica privada anterior fica separada.

Validação de fontes restaurada em 26/09/2026: execute
`./tools/validation/securityops-validate quick` para o gate independente A/B, ou
`./tools/validation/securityops-validate full` para incluir as simulações do grafo
fixado. O avaliador usa o mesmo seletor de fontes de `config.scm` e guarda
recibos privados em `.dsh/state/`, ignorado pelo Git. Os 50 testes focados
passaram em dois contextos independentes; isso não aprova o projeto inteiro.
A sintaxe Bash agora é verificada separadamente para cada um dos cinco scripts
em cada rodada: um único `bash -n` com vários nomes só analisa o primeiro.
ShellCheck continua recebendo a lista completa. As verificações Bash agrupadas
anteriores não comprovam cobertura dos outros quatro scripts. Esta correção
não qualifica a compilação nem a ISO.
Se ShellCheck não estiver nos perfis-base admitidos, ambos os modos aceitam
`--check-tools-profile /gnu/store/...-profile` somente para um perfil imutável
validado contendo apenas ShellCheck, não como extensão arbitrária de PATH.
Um perfil descartável criado com o pacote já existente no Store passou nessa
admissão, sem mudar o perfil do host ou suas chaves.
Quando o Guix pessoal divergir dos canais do repositório, use
`./tools/validation/securityops-validate quick --pinned-guix` (ou `full`), acrescentando
`--check-tools-profile /gnu/store/...-profile` se necessário. A opção resolve
`channels.guix` uma vez para o avaliador, compara nomes, URLs, branches, commits
e introduções com o perfil imutável resultante e usa esse perfil junto ao perfil
do sistema em todas as etapas A/B e full, sem fallback para o perfil pessoal.
Guix de bootstrap e ferramentas selecionadas são registrados separadamente.
A resolução pode buscar código dos canais e gravar no Store; não atualiza
perfis do host, pins ou chaves, nem constrói ISO. O limite existente de 20 GiB
livres vale tanto para o disco do worktree quanto para `/gnu/store`: usar outro
SSD não muda a localização do Store. O modo full ainda executa as simulações
fixadas da própria CLI. Igualdade dos metadados não autentica o publicador;
os avisos de confiança dos canais continuam limitando as conclusões de release.
Sem a opção, o comportamento anterior é preservado. Antes da primeira validação
em um checkout novo, execute `./securityopsctl prepare-validation`: o comando
apenas cria/verifica `out/.iso-build.lock`, sem chamar Guix, alterar settings ou
iniciar build. A CLI e os dois wrappers compartilham a abertura sem seguir links
simbólicos e sem espera por locks ocupados. Locks existentes precisam ser
arquivos regulares do usuário, com um único link e modo `0600`; repositório e
`out/` devem pertencer ao usuário e não permitir escrita de grupo/outros.
Locks inseguros são recusados, nunca corrigidos, apagados ou substituídos
automaticamente. O avaliador continua exigindo lock preexistente e mantém
todas as verificações de fontes e ferramentas. O worktree isolado de reparo
agora rastreia as 34 entradas revisadas da GUI/verificador de pacotes.
Isso não autentica publicadores nem fornece um runtime compilado. O filho órfão
do teste histórico foi corrigido com prontidão e EOF do pipe, permitindo ao mesmo
supervisor `flock` recolher o filho. Três regressões cobrem retorno normal, falha
de asserção e `KeyboardInterrupt` Python injetado; não simulam sinais reais nem
queda de energia.

Hardening restaurado em 26/09/2026: os módulos ausentes foram encontrados no
mesmo checkout histórico da Fase 48 usado pelo avaliador. A política compartilhada
agora alimenta o live e as configurações geradas pelo instalador; a receita do
kernel declara a verificação estrita de Kconfig antes e depois da compilação.
HZ=1000, IOMMU estrito e VFIO sem IOMMU desativado são políticas solicitadas,
não comprovação em hardware. No checkpoint de restauração, o quick passou nas 22 verificações, incluindo
189 testes em cada contexto A/B, sem falhas, erros ou skips. Os testes também
constroem o fechamento Guix dos módulos importados pelo helper e verificam
entradas sintéticas nesse builder. Isso não compila o kernel nem executa suas
fases completas. Naquele checkpoint, o full passou nas suítes A/B de fontes,
mas falhou em `full-a`; `full-b` não foi executado. Grafo fixado, live e instalação
continuam pendentes.
O reparo não altera pins, versão do kernel, configuração do host ou aprovação
de produção.
Não substitua pré-requisitos nem ignore verificações para obter PASS.
Nenhuma nova ISO foi construída.

Reparo da descoberta na validação completa, 2026-09-26: `securityopsctl validate --full`
executa os três dry runs fixos por uma entrada Scheme interna no mesmo
`guix time-machine` fixado. A enumeração local fica restrita a
`securityops/packages`; imports explícitos e assets relativos mantêm o checkout.
Isso evita descobrir recursivamente `out/cache` e scripts de testes. Canais,
ordem dos substitutos, fallback e lock são preservados. Argumentos inesperados,
caminhos não canônicos, `GUIX_PACKAGE_PATH` não vazio e qualquer
`GUIX_EXTENSIONS_PATH` herdado são recusados. Caminhos Guile de módulos, módulos
compilados e extensões devem resolver sob itens Store de root não graváveis,
preservando os caminhos do avaliador. Isso verifica localização, não admite código
nem comprova as permissões de todos os descendentes. Variáveis Guile presentes
mas vazias são recusadas; ausentes mantêm o padrão upstream. Configurações não
são descartadas silenciosamente. O caminho do instalador gerado é dinâmico
e deve identificar um arquivo privado regular com um único link. Isso
não é sandbox Scheme, autenticação de canais, build de kernel/ISO nem aprovação
de live/instalação.

Validação deste reparo: os dez testes focados passam no Guix atual e no fixado.
O quick/full oficial agora para nas fontes A (199 testes, uma falha, sem erros
ou skips), pois o perfil Guix atual do usuário deixou de fornecer
`(nongnu packages linux)`. Este reparo não alterou o perfil do host. Um diagnóstico
separado em cópia nova, usando o perfil imutável anterior, passa nos 199 testes;
seu diagnóstico da CLI completa os três dry runs fixados em 880 segundos.
Isso não substitui a aprovação A/B oficial nem autentica canais. O timeout
anterior de 300 segundos foi preservado. Nenhuma nova ISO foi construída.

Reparo da descoberta no build normal, 2026-09-27: os dois caminhos de `build.sh`
usam `securityops/build-image.scm` para limitar a descoberta local de pacotes a
`securityops/packages`, preservando o checkout para imports. A entrada aceita
apenas a raiz canônica e argumentos positivos `--max-jobs=N` / `--cores=N`,
mantendo ordem e repetições. Tipo de imagem, label, configuração, ordem dos
substitutos e fallback são fixos internamente; time-machine externo e lock não
mudam. Entradas inesperadas de descoberta são recusadas. Ao contrário do
validador completo, essa entrada constrói de verdade quando invocada normalmente:
seus testes de regressão encerram antes de retornar um sistema e usam um socket
de daemon inexistente. Eles não comprovam build de ISO nem boot. O validador
completo continua separado, inalterado e exclusivo para dry runs.
O reparo não cria sandbox Scheme nem adiciona ao build normal a proteção de
ambiente do validador completo; use um ambiente de build controlado.

O usuário live é `securityops`. Não existe senha estática no ISO. A cada
inicialização, o sistema gera uma senha nova e a exibe somente no VT1 local
confiável. Use `Ctrl+Alt+F1` para consultá-la e `Ctrl+Alt+F7` para voltar ao
login. A mesma senha daquela inicialização é exigida pelo `sudo`; a conta root
permanece bloqueada.

No `tuigreet`, pressione **F3** para escolher entre **Sway** (Wayland, padrão),
**XMonad + XLibre** (X11 sobre o servidor XLibre real fixado) e **KDE Plasma**
(Wayland). O Xorg comum não é renomeado como XLibre. A escolha do instalador
gera somente a pilha solicitada e registra o valor em
`/etc/securityops/desktop`. Como a troca de layout antes da entrada de senhas é
autenticada somente pelo IPC Sway pertencente ao usuário ou por um VT real,
usuários do live XMonad/KDE devem encerrar a sessão e selecionar Sway (ou usar
um VT) antes de iniciar o instalador. Consulte
[`docs/DESKTOPS.pt-BR.md`](docs/DESKTOPS.pt-BR.md).

Para instalar em disco, execute `security-ops-install`. O instalador transforma
a senha administrativa em um verificador yescrypt por descritor protegido,
mantém esse verificador somente em estado volátil privado do root e o envia por
stdin ao `/etc/shadow` do alvo apenas depois de uma inicialização bem-sucedida.
A configuração declarativa e o store mantêm tanto root quanto o usuário
administrativo bloqueados; texto puro, verificador e segredo LUKS não entram em
argv, ambiente ou log. No modo LUKS2, o volume raiz é criptografado, mas a
partição de sistema UEFI permanece sem criptografia; a senha LUKS é apagada das
variáveis do instalador imediatamente depois que o mapeamento abre.
O slot LUKS2 usa Argon2id com parâmetros fixos (`t=4`, `64 MiB`, `p=1`). A senha
LUKS deve ter de 20 a 254 bytes US-ASCII imprimíveis. Como o primeiro prompt
`cryptomount` do GRUB 2.14 aparece antes do mapa de teclado instalado, o
instalador muda de forma visível a entrada da senha LUKS para o layout US e
restaura depois o layout escolhido. A senha administrativa aceita de 12 a 128
bytes US-ASCII imprimíveis. Antes de anunciar sucesso, o instalador sincroniza
o shadow, a raiz e a ESP e fecha somente os mounts/mapeamentos que ele próprio
criou e cuja identidade ainda consegue provar.
O alvo deve ter pelo menos 64 GiB; mídias live, mounts, swap, holders e política
Secure Boot não verificável são recusados antes da gravação.

## Ferramentas incluídas na imagem

Além do kit de pentest/hardening curado, a imagem r13 inclui as ferramentas
nativas do canal **securityops** (Evelin, Esquema, Zupt, Turbo Recorder,
Torando e mirim) e os pacotes de terceiros reempacotados abaixo, com as
versões exatas publicadas no canal (`9917c7e1`):

| Ferramenta | O que é | Versão | Licença |
|---|---|---|---|
| **Burp Suite Community** | Kit de teste de segurança de aplicações web (JAR oficial da PortSwigger no OpenJDK 21) | 2026.10.1 | EULA PortSwigger |
| **Maltego Graph** | Suite de OSINT / análise de vínculos (distribuição Linux oficial da Maltego) | 4.14.0 | EULA proprietário da Maltego |
| **PhotoCraft** | Edição de fotos | 0.9.0 | binários ArtCraft; termos por aplicativo |
| **VectorCraft** | Gráficos vetoriais | 0.10.0 | binários ArtCraft; termos por aplicativo |
| **FilmCraft** | Edição de vídeo | 0.7.2 | binários ArtCraft; termos por aplicativo |
| **LightCraft** | Gerenciamento de fotos | 0.8.0 | binários ArtCraft; termos por aplicativo |
| **PdfCraft** | Ferramentas de PDF | 0.8.0 | binários ArtCraft; termos por aplicativo |
| **EffectCraft** | Efeitos visuais | 0.10.0 | binários ArtCraft; termos por aplicativo |
| **DesignCraft** | Design gráfico | 0.8.0 | binários ArtCraft; termos por aplicativo |
| **FigCraft** | Diagramas e figuras | 0.6.0 | binários ArtCraft; termos por aplicativo |
| **WordCraft** | Processamento de texto | 0.7.0 | binários ArtCraft; termos por aplicativo |
| **SoundCraft** | Produção de áudio | 0.5.0 | binários ArtCraft; termos por aplicativo |
| **DeckCraft** | Apresentações | 0.7.0 | binários ArtCraft; termos por aplicativo |
| **CADCraft** | CAD 2D/3D | 0.7.0 | binários ArtCraft; termos por aplicativo |
| **GridCraft** | Planilhas | 0.7.0 | binários ArtCraft; termos por aplicativo |

O **Tor Browser 16.0.1** vem da receita revisada do canal securityops e as
versões completas de todos os 245 pacotes da imagem estão documentadas em
`docs/PACKAGES.md` e na tabela completa do site guix.securityops.co.

## Licenciamento

As declarações locais inspecionadas de Security Ops OS, Evelin,
VaptVupt, libvuptsdk, Mirim e Cofre Soberano PQ descrevem uma rota comercial
separada para direitos próprios controlados, além da opção pública aplicável.
O Esquema permanece GPL-3.0-or-later e a fonte canônica observada na Fase 30 não
declara opção comercial separada. O VaptVupt Codec preserva
GPL-3.0-or-later como opção pública. O BTP permanece Apache-2.0/CC-BY-4.0 e o
checkout inspecionado não declara rota comercial separada. Para os projetos
elegíveis, as duas rotas independentes são:

1. a licença pública exata do projeto ou arquivo (geralmente AGPL; há exceções
   GPL/MIT descritas na matriz); ou
2. um contrato comercial separado, assinado pelo titular e pelo licenciado.

`LICENSE-COMMERCIAL` é um aviso de escopo e contato, não uma concessão pública
de direitos proprietários. GNU Guix, Linux, Coreutils, QEMU, firmware,
dependências e demais componentes preservam suas próprias licenças. Consulte
[`docs/LICENSING.pt-BR.md`](docs/LICENSING.pt-BR.md) e
[`docs/OS-IDENTITY.pt-BR.md`](docs/OS-IDENTITY.pt-BR.md).

Contato para licenciamento comercial: `sac@securityops.co`.

Exceções explícitas: `securityops/installer/cow-system-init.scm` e
`securityops/bootloader.scm` derivam de código de instalador/bootloader do GNU
Guix e permanecem somente sob **GPL-3.0-or-later**. Nenhuma opção de
relicenciamento comercial da Security Ops é afirmada para direitos derivados
de upstream nesses arquivos.

## Construção e verificação local

```sh
./securityopsctl validate --full
./securityopsctl build --bundle --jobs 4 --cores 6
```

O build deve ser feito a partir dos canais fixados em `channels.guix`. Um teste
indisponível ou bloqueado não é PASS. Este trabalho não publica arquivos,
releases, tags ou commits remotos.

O servidor XLibre agora vem dentro do próprio canal `securityops` autenticado;
todas as entradas do fecho de canais carregam sua introdução publicada. Isso
elimina a exceção de autenticação do checkpoint anterior da Fase 29.

Guix pode avisar que `small-guix` “não é confiável” quando a introdução ainda
não está no `trusted-channels.scm` do usuário que executa o comando. A entrada
fixada continua contendo a introdução publicada e a autenticação do commit
permanece ativa. Não substitua isso por `--disable-authentication`.

O README em inglês contém a lista completa de pacotes, teclas e instruções de
gravação: [`README.md`](README.md).
