# Nexa Admin API (Pacote 1)

Serviço Node.js privado em desenvolvimento, separado do site estático.

Necessita das variáveis protegidas `DATABASE_URL`, `SESSION_SECRET` e `ADMIN_PASSWORD_SCRYPT` no Render. O usuário deve configurar a senha fora do chat.

Contém rotas de login, sessão, logout, rascunhos e revisões. Publicação online desativada até os testes. A integração do editor visual e o deploy protegido ainda estão pendentes.

NÃO incorporar segredos ao HTML do site público. Projeto Neon exclusivo: `nexa-digital-academy-admin`.
