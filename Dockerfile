FROM node:20-alpine
WORKDIR /app
COPY package.json ./
COPY src ./src
USER node
EXPOSE 8443
CMD ["node", "src/index.js"]
