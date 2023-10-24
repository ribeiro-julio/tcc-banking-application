# tcc-banking-application
Projeto TCC - Banking application

## Como rodar local:

Necessário ter `node` e `Python3.10` instalados na máquina
Necessário banco de dados Postgres instalado

### API
- Navegue para a pasta `/api`
- Instale as dependências com o comando `npm install`
- Rode as migrações no banco de dados com o comando `npx prisma migrate reset`
- Execute a API com o comando `npm start`

### CLI
- Navegue para a pasta `/cli`
- Crie um ambiente virtual com o comando `python3 -m venv venv`
- Inicie o ambiente virtual com o comando `source venv/bin/activate`
- Instale as dependências com o comando `pip install -r requirements.txt`
- Navegue para a pasta `/api/src`
- Execute o arquivo `main.py` com o comando `python3 main.py`

### Testes
- Navegue para a pasta `/api-tests`
- Com a API rodando, execute o arquivo `login.js` com o comando `node login.js`
