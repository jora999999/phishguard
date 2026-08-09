# Étape 1 : build Vite
FROM node:20-slim AS build
WORKDIR /app

# Accept VITE_API_URL as build arg (defaults to http://localhost:8000)
ARG VITE_API_URL=http://localhost:8000

COPY package.json ./
RUN npm install --no-audit --no-fund
COPY index.html vite.config.js ./
COPY src ./src
RUN VITE_API_URL=$VITE_API_URL npm run build

# Étape 2 : servir le statique avec nginx (+ proxy /api)
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
