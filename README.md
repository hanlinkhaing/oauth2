# OAuth 2.0 Server

### Develop on Local

1. Create .env and copy contents from .env.dev
2. Run `docker compose up` for Postgresql (according to `.env.dev`, it will run on port 5433)
3. Run `npx prisma migrate dev` to migrate the schema on the DB
4. Then, run `npx prisma generate` to generte prisma client
5. Run the project with `yarn/npm start dev` and test it on port 5000
