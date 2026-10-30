# Configurando SSO e TOTP

O IndexFin2 suporta SSO OpenID Connect com Google e Microsoft Entra ID. Um provedor só aparece na tela de login quando seu `CLIENT_ID` e `CLIENT_SECRET` estiverem configurados. SSO autentica uma conta previamente aprovada: o e-mail retornado pelo provedor deve corresponder a exatamente um usuário cadastrado e ativo. O primeiro login vincula o identificador estável do provedor a esse usuário.

## Google

1. Crie um projeto no Google Cloud e configure a tela de consentimento OAuth.
2. Crie um cliente OAuth do tipo aplicação Web.
3. Adicione como URI de redirecionamento autorizado:
   - Local: `http://127.0.0.1:5000/login/google/callback`
   - Produção: `https://SEU-DOMINIO/login/google/callback`
4. Configure `GOOGLE_CLIENT_ID` e `GOOGLE_CLIENT_SECRET` no ambiente onde o Flask roda.

## Microsoft

1. Registre uma aplicação no Microsoft Entra ID e configure a plataforma Web.
2. Adicione os URIs de redirecionamento:
   - Local: `http://127.0.0.1:5000/login/microsoft/callback`
   - Produção: `https://SEU-DOMINIO/login/microsoft/callback`
3. Crie um client secret e configure `MICROSOFT_CLIENT_ID` e `MICROSOFT_CLIENT_SECRET`.
4. Defina `MICROSOFT_TENANT_ID` como `common` para permitir contas pessoais e organizacionais, ou use o tenant ID da organização para restringir o login a ela.

Os endereços cadastrados no provedor devem coincidir exatamente com o host usado pelo navegador. Em produção, use HTTPS.

## TOTP obrigatório

Operadores (incluindo comercial e financeiro) e auditores precisam configurar TOTP no primeiro login ou após redefinição. O perfil admin está temporariamente sem exigência de TOTP por decisão do projeto. Google Authenticator e Microsoft Authenticator são compatíveis. A pessoa informa a chave manualmente no app autenticador e confirma o primeiro código de 6 dígitos antes de receber uma sessão autenticada. As chaves TOTP ficam no banco da aplicação; proteja e faça backup seguro desse banco.

O admin pode redefinir o autenticador pelo painel **Usuários**; o usuário terá de configurá-lo novamente. A recuperação de TOTP deve ser feita por um administrador autorizado. Não há códigos de recuperação na versão atual.

## Variáveis de ambiente

Use [`.env.example`](./.env.example) como referência e configure as variáveis no terminal, serviço de hospedagem ou gerenciador de segredos. A aplicação não carrega `.env` automaticamente.

## Iniciar localmente no Windows

Abra o arquivo `Iniciar IndexFin.bat` na pasta do projeto com duplo clique.
Quando o servidor iniciar, acesse `http://127.0.0.1:5000`. Mantenha a janela
aberta durante o uso; fechá-la ou parar o processo encerra o servidor. Se a
página mostrar `ERR_CONNECTION_REFUSED`, inicie novamente o servidor.

O inicializador usa as variáveis de ambiente já configuradas para sua conta
Windows e não contém chaves ou credenciais. Para armazenar CPFs no ambiente de
desenvolvimento, configure `CPF_ENCRYPTION_KEY` como variável persistente do
usuário antes de iniciar o app.

O servidor local escuta apenas em `127.0.0.1` e inicia sem modo de depuração.
Para depurar intencionalmente, defina `APP_DEBUG=true` apenas em ambiente local.

Exemplo de PowerShell para configurar SSO localmente:

```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
$env:GOOGLE_CLIENT_ID = "valor-do-cliente"
$env:GOOGLE_CLIENT_SECRET = "segredo-do-cliente"
$env:MICROSOFT_CLIENT_ID = "valor-do-cliente"
$env:MICROSOFT_CLIENT_SECRET = "segredo-do-cliente"
$env:MICROSOFT_TENANT_ID = "common"
python app.py
```

O `SECRET_KEY` usado em produção precisa ser fixo, aleatório e guardado fora do repositório. Defina `APP_ENV=production` e `COOKIE_SECURE=true` quando o site estiver servido exclusivamente por HTTPS. Sem as credenciais dos provedores, o login por usuário e senha continua disponível e os botões SSO ficam ocultos.

## CPF e CNPJ

Usuários novos informam CPF válido; CPFs existentes são solicitados no próximo login. O CPF é criptografado no banco e a verificação de unicidade usa um HMAC, sem armazenar o número em texto puro. Para isso, configure `CPF_ENCRYPTION_KEY` com uma chave Fernet persistente, separada de `SECRET_KEY`. Gere a chave uma vez:

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Guarde o valor em um gerenciador de segredos/ambiente seguro e mantenha um backup protegido. **Perder ou trocar essa chave torna os CPFs existentes irrecuperáveis.** Em produção, o app não inicia sem uma chave válida.

Empresas e fornecedores precisam de CNPJ válido, inclusive no padrão alfanumérico. No painel **Usuários**, o administrador pode informar o CNPJ real das empresas e fornecedores já existentes ou cadastrá-los com o CNPJ. Cadastros de cliente também exigem o CNPJ da empresa. Fornecedores sem CNPJ não podem ser selecionados para novas cotações.

## Execução em produção no Windows

Use Waitress como servidor WSGI, atrás de um proxy reverso (por exemplo, IIS com ARR) que forneça HTTPS, redirecione HTTP para HTTPS e encaminhe `Host`, `X-Forwarded-Proto` e `X-Forwarded-For`. O app confia nesses cabeçalhos de um único proxy; mantenha Waitress limitado a `127.0.0.1:8080` e não exponha essa porta à rede.

Instale as dependências e configure as variáveis no PowerShell antes do primeiro início:

```powershell
python -m pip install -r requirements.txt
$env:APP_ENV = "production"
$env:COOKIE_SECURE = "true"
$env:DATABASE_PATH = "C:\IndexFin2\data\indexfin2.db"
$env:SECRET_KEY = [Environment]::GetEnvironmentVariable("SECRET_KEY", "User")
$env:CPF_ENCRYPTION_KEY = [Environment]::GetEnvironmentVariable("CPF_ENCRYPTION_KEY", "User")
$env:BOOTSTRAP_ADMIN_EMAIL = Read-Host "E-mail do administrador"
$securePassword = Read-Host "Senha inicial do administrador (mínimo 16 caracteres)" -AsSecureString
$env:BOOTSTRAP_ADMIN_PASSWORD = [Net.NetworkCredential]::new("", $securePassword).Password
python serve.py
```

Crie uma senha inicial exclusiva; o servidor remove a senha e o e-mail de bootstrap do ambiente do processo após inicializar o banco. O usuário `admin` é criado somente se o banco estiver sem usuários. Use um banco de produção novo: a inicialização de produção não cria os dados de demonstração. Não copie um banco de desenvolvimento sem remover contas de demonstração e redefinir todas as senhas. Proteja o arquivo SQLite e seus backups com permissões restritas. O usuário administrador atualmente não exige TOTP por decisão do projeto; reative essa exigência antes de expor o sistema à internet.

O servidor Waitress não fornece TLS. Sem o proxy HTTPS e os cabeçalhos encaminhados corretamente, cookies seguros e callbacks SSO não funcionarão corretamente; a implantação ainda não está pronta para acesso público.
