# Opções de desktop

O Security Ops OS oferece três sessões explícitas no login live e no
instalador guiado:

| Opção | Pilha gráfica | Uso pretendido |
|---|---|---|
| Sway | Wayland/wlroots nativo | Padrão, menor superfície gráfica e caminho de recuperação mais simples |
| XMonad + XLibre | X11 sobre o servidor XLibre fixado | Tiling controlado por teclado e compatibilidade X11 |
| KDE Plasma | Wayland/KWin nativo | Desktop integrado completo |

Na tela live do `tuigreet`, pressione **F3** para escolher. Sway é o padrão
explícito quando nenhuma alternativa é selecionada. O nome de usuário pode ser
lembrado, mas senha e sessão não são persistidas; a senha live é recriada a cada
boot e exibida somente no VT1 confiável.

Os launchers são objetos imutáveis do store Guix. Sway inicia o binário Sway
fixado, KDE inicia `startplasma-wayland` e XMonad executa `xinit` contra um
wrapper construído com `xlibre-configuration`. Xorg comum nunca é renomeado ou
apresentado como XLibre. Diagnósticos ficam em
`$XDG_STATE_HOME/securityops/sessions/`, e não em arquivos previsíveis de
`/tmp`.

## Comportamento do instalador

A configuração instalada gerada contém apenas o conjunto do desktop escolhido.
Para `xmonad-xlibre`, o serviço GDM é reescrito explicitamente para o servidor
e o conjunto limitado de drivers XLibre fixados. Se o canal ou módulo XLibre
não estiver disponível, a avaliação falha; não existe fallback silencioso para
Xorg. `/etc/securityops/desktop` registra `sway`, `xmonad-xlibre` ou `kde`.

A entrada de senhas continua fail-closed. O instalador só consegue provar e
alterar o mapa de teclado live pelo socket IPC Sway pertencente ao usuário ou
por um VT real. Ao usar XMonad ou KDE no live, encerre a sessão e selecione Sway
(ou use um VT real) antes de executar `security-ops-install`. Nenhuma senha é
solicitada antes dessa verificação.

## Fronteiras de segurança

A escolha de desktop não cria uma célula, contêiner ou VM. X11 permite que
clientes no mesmo display observem ou injetem muito mais entrada e estado de
janelas que clientes Wayland nativos; use XMonad + XLibre somente quando essa
troca de compatibilidade for aceitável. A pilha maior de serviços e plugins do
KDE também amplia a superfície em relação ao Sway padrão. XWayland preserva
semântica X11 entre seus clientes mesmo dentro de Sway ou KDE.

O servidor XLibre agora vem dentro do canal securityops, fixado no commit
`34a0099058eada895d92069f36feb2267ebfa203` com sua introdução publicada; o
canal separado guix-xlibre foi aposentado. O pin anterior de apenas
integridade determinística (Fase 29) não se aplica mais.
