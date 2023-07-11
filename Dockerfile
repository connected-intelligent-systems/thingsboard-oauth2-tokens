FROM node:18.12.0

WORKDIR /app

COPY package.json .
COPY package-lock.json .

RUN npm install --production

COPY index.js .

CMD [ "npm", "start" ]

EXPOSE 3000