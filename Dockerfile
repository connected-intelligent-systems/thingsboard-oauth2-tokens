FROM node:20.11.0-alpine3.18

RUN apk --no-cache add curl
RUN adduser  -D user -u 2011


WORKDIR /app

COPY package.json .
COPY package-lock.json .

RUN npm install --production

COPY index.js .

USER node

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 CMD curl -f http://localhost:3000 || exit 1

CMD [ "npm", "start" ]

EXPOSE 3000