FROM node:20-alpine

WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/index.html ./index.html
COPY frontend/tsconfig.json ./tsconfig.json
COPY frontend/tsconfig.node.json ./tsconfig.node.json
COPY frontend/vite.config.ts ./vite.config.ts
COPY frontend/src ./src
COPY frontend/public ./public

ARG VITE_API_BASE=http://localhost:8000/api
ENV VITE_API_BASE=${VITE_API_BASE}

RUN npm run build

EXPOSE 4173

CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "4173"]

