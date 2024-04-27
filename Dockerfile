FROM node:18.17.1
WORKDIR /home/app/oauth

COPY package.json ./
RUN yarn install

COPY . .
COPY .env ./

EXPOSE 5000

RUN npx prisma generate
CMD [ "yarn", "dev" ]