# gate v2 dry-run fixture (probe repository only; not a candidate)
FROM node@sha256:8ec5d7557396cfe32d21c3f9c13072355ceab22b584578ca4bb28af31120cffe AS base
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY . .
FROM base AS check
CMD ["node", "--test", "test/"]
FROM base AS preview
USER node
CMD ["node", "server.mjs"]
