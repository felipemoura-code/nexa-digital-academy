# Nexa Admin PRO — Pacote 1

Status: desenvolvimento em andamento. A loja pública no branch main permanece inalterada.

## Arquitetura aprovada
- Site público atual: Render static site conectado à branch main.
- Editor do administrador: interface separada; jamais publicar sem autenticação do servidor.
- Backend futuro: serviço privado para autenticação, validação e publicação.
- Banco: projeto separado do Neon exclusivo da Nexa.
- GitHub: publicação feita pelo backend com credenciais de menor privilégio e registro de versões.
- Pagamentos e entrega: continuam sob responsabilidade da Kiwify.

## Decisões de segurança
1. Nunca inserir credenciais de GitHub, Render ou banco no HTML público.
2. Login deve ocorrer no servidor com sessões protegidas e autorização por operação.
3. Manter revisão, histórico e opção de restauração.
4. Proteger o catálogo de links externos inválidos e de preços negativos.
5. Não confundir preço exibido na loja com preço efetivo do checkout.
6. Não reutilizar o banco do projeto Monitor de Vendas Unificado.

## Implementação local 3.0
O editor v3 foi empacotado separadamente para testes locais e inclui:
- histórico das últimas 12 versões;
- restauração confirmada;
- migração dos dados locais da v2;
- verificações mais rígidas de links oficiais da Kiwify;
- relatório de revisão do catálogo;
- importação/exportação JSON.

A integração online será considerada pronta somente após autenticação, persistência e testes de ponta a ponta.