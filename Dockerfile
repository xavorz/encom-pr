FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install --production

COPY . .

# Crear directorio de datos si no existe
RUN mkdir -p data

EXPOSE 3000

CMD ["npm", "start"]
