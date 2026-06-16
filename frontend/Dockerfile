FROM node:20-alpine AS build
WORKDIR /app

# Se copia solo package.json para invalidar bien la caché cuando cambian dependencias.
COPY package.json .npmrc* ./

# Se fuerza instalación completa y se valida que Vite exista antes de compilar.
RUN npm install --include=dev --registry=https://registry.npmjs.org/ \
    && ./node_modules/.bin/vite --version

COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
