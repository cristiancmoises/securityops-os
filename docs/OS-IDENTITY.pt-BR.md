# Identidade do Security Ops OS

O Security Ops OS é uma distribuição GNU/Linux completa, montada e gerenciada
declarativamente com GNU Guix. O Guix é uma base importante para construção,
pacotes e atualizações; ele não é o nome do produto. O Linux continua sendo o
kernel.

Os sistemas live e instalado expõem uma identidade consistente:

```text
$ uname
Linux
$ uname -s
Linux
$ uname -o
Security Ops OS
$ uname -a
Linux <hostname> <release>-SecurityOps <kernel-build> x86_64 Security Ops OS
```

O `uname` sem opção e o `uname -s` preservam intencionalmente a resposta padrão
com o nome do kernel. Trocá-la pelo nome da distribuição falsearia a API do
kernel e quebraria software que detecta Linux. `uname -r`, `uname -v` e
`uname -m` também continuam mostrando valores reais do kernel ou do hardware.
Apenas o campo `-o`/`--operating-system`, extensão GNU do Coreutils, recebe a
marca da distribuição. Assim, `uname -a` inclui Security Ops OS sem corromper os
demais campos. A procedência GNU/Linux e Guix permanece em `/etc/os-release`,
`/etc/issue` e nesta documentação, em vez de ser anexada ao nome solicitado do
produto.

Esse comportamento vem da definição de pacote compilado do código-fonte
`securityops-coreutils`, em `securityops/branding.scm`. Não é alias de shell,
função, variável de ambiente nem wrapper mutável. A construção falha se o ponto
de alteração no código upstream mudar, executa a suíte de testes do Coreutils e
adiciona verificações para o comportamento padrão, `-s`, `-o` e `-a`.

O `/etc/os-release` começa com:

```text
NAME="Security Ops OS"
ID=securityops
ID_LIKE=guix
PRETTY_NAME="Security Ops OS 1.14.0"
```

Ele também registra `SECURITYOPS_SYSTEM_MANAGER="GNU Guix"` e
`SECURITYOPS_KERNEL="Linux"`. O `/etc/issue` identifica o Security Ops OS e sua
base GNU/Linux gerenciada pelo Guix. O hostname do sistema live é
`securityops-live`; o sistema instalado usa o hostname escolhido na instalação.

## Limite de licenciamento

A configuração original do Security Ops OS e os outros componentes autorais de
primeira parte são oferecidos segundo os termos de licenciamento duplo
AGPL-3.0-or-later/comercial do projeto. Componentes de terceiros preservam suas
próprias licenças. Em particular, GNU Coreutils e o binário `uname` modificado
continuam sob GPL-3.0-or-later; o Security Ops OS não relicencia e não pode
relicenciá-los sob sua licença comercial.

A identidade declara a autoria do produto sem ocultar sua procedência. Ela não
implica que o Security Ops OS tenha criado o Linux, o GNU Coreutils ou o GNU
Guix.
