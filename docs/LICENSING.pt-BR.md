# Licenciamento do Security Ops OS

A definição própria da imagem do Security Ops OS está disponível sob
`AGPL-3.0-or-later` ou por contrato comercial escrito e separado, assinado pelo
titular dos direitos aplicável e pelo licenciado. A licença pública completa
está em [`LICENSE`](../LICENSE) e
[`LICENSE-AGPL-3.0`](../LICENSE-AGPL-3.0).
[`LICENSE-COMMERCIAL`](../LICENSE-COMMERCIAL) é apenas um aviso de consulta e
escopo; ele não concede publicamente uma licença comercial.

Dois arquivos estão expressamente fora desse escopo de licenciamento duplo:
`securityops/installer/cow-system-init.scm` e `securityops/bootloader.scm`
são derivados restritos do instalador/bootloader do GNU Guix e são distribuídos
somente sob `GPL-3.0-or-later`. A Security Ops não afirma uma opção de
relicenciamento comercial para direitos derivados de upstream que não controla
com exclusividade.

“Uso comercial” e “licença comercial” são conceitos diferentes. A AGPL
permite uso comercial quando suas condições são cumpridas. O contrato
comercial separado é uma alternativa para o código próprio quando o
licenciado precisa de outros termos. Os direitos exatos existem somente no
contrato assinado.

## Fronteira da imagem agregada

O Security Ops OS é uma distribuição Linux completa, construída e atualizada
com GNU Guix. Sua ISO reúne obras de muitos titulares. Nem a AGPL nem um
contrato comercial da Security Ops substitui as licenças dos componentes.
Linux, GNU Guix, bootloaders, desktop, firmware, bibliotecas, aplicativos,
fontes e todos os outros pacotes mantêm seus próprios termos.

Os repositórios locais inspecionados declaram opções independentes:

| Projeto | Opção pública | Opção comercial separada |
|---|---|---|
| Definição própria da imagem do Security Ops OS | AGPL-3.0-or-later | Exige contrato assinado específico |
| `securityops/installer/cow-system-init.scm` (helper derivado do GNU Guix) | GPL-3.0-or-later | Nenhuma afirmada; direitos derivados de upstream ficam excluídos |
| `securityops/bootloader.scm` (instalador EFI de marca derivado do GNU Guix) | GPL-3.0-or-later | Nenhuma afirmada; direitos derivados de upstream ficam excluídos |
| Evelin | AGPL-3.0-or-later | Exige contrato assinado do Evelin |
| Esquema | GPL-3.0-or-later | Nenhuma declarada pela fonte canônica observada na Fase 30 |
| VaptVupt | Escopo da aplicação AGPL; escopo do codec GPL | Pode abranger somente direitos próprios controlados mediante contrato assinado |
| VaptVupt Codec | GPL-3.0-or-later | Pode abranger somente direitos próprios controlados mediante contrato assinado |
| libvuptsdk | AGPL-3.0-or-later | Exige contrato assinado do libvuptsdk |
| Mirim | Escopo do motor AGPL-3.0-only; arquivos de suporte expressamente marcados continuam MIT | Exige contrato assinado do Mirim para direitos próprios controlados |
| Cofre Soberano PQ | AGPL-3.0-or-later | Exige contrato assinado do Cofre Soberano PQ |
| BTP | Implementação Apache-2.0; especificação CC-BY-4.0 | Nenhuma opção separada declarada no checkout inspecionado |
| Código do canal Guix Security Ops | GPL-3.0-or-later | Nenhuma opção declarada neste checkout |

A tabela registra as declarações locais inspecionadas; ela não concede direitos.
Um contrato de um projeto não cobre outro, a menos que isso esteja expresso.
Ferramentas não listadas precisam ser avaliadas pelo repositório canônico e
pelo contrato assinado; mesmo titular, empacotamento no Guix ou inclusão na ISO
não cria licença comercial.

A definição de pacote Guix registra a opção pública distribuível. Ela não
coloca contrato comercial privado ou chave no store do Guix e não modifica a
licença upstream.

Consultas: `sac@securityops.co`. Este texto resume a política do repositório e
não constitui aconselhamento jurídico.
