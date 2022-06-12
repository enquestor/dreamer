FROM node:17.9.1-alpine3.15 as base

WORKDIR /node

COPY ../package*.json ./

FROM base as test
RUN npm ci
COPY . .
CMD [ "npm", "run", "test" ]

FROM base as prod
RUN npm ci --production
COPY . .
EXPOSE 3000
CMD [ "npm", "run", "prod" ]